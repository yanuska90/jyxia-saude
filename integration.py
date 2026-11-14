"""Restricted synthetic integration sandbox, not a FHIR conformance validator."""
import hashlib
import json
import copy
from datetime import datetime, timezone

PATIENT = 'SYN-P01'
SOURCES = {'lab-demo': {'Patient/LAB-P01'}, 'hospital-demo': {'Patient/HOSP-P01'}}
TYPES = {'Observation', 'DiagnosticReport', 'AllergyIntolerance', 'Condition',
         'Procedure', 'Encounter', 'MedicationStatement'}

class IntegrationError(ValueError):
    pass

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()

def label(concept):
    return concept.get('text') or next((x.get('display') or x.get('code')
                                      for x in concept.get('coding', [])), 'Não informado')

def normalize(source, bundle):
    """Accept only explicit source/patient mappings. No fuzzy/CPF matching."""
    if source not in SOURCES:
        raise IntegrationError('Fonte não autorizada para este ambiente sintético.')
    if not isinstance(bundle, dict) or bundle.get('resourceType') != 'Bundle' or bundle.get('type') != 'collection':
        raise IntegrationError('Use um Bundle collection do subconjunto de teste.')
    entries = bundle.get('entry', [])
    if not isinstance(entries, list) or not 1 <= len(entries) <= 100:
        raise IntegrationError('Envie entre 1 e 100 recursos.')
    results = []
    seen = set()
    for entry in entries:
        resource = copy.deepcopy(entry.get('resource', {}))
        kind = resource.get('resourceType')
        if kind not in TYPES:
            raise IntegrationError('Tipo de recurso fora do subconjunto suportado.')
        rid = resource.get('id')
        version = resource.get('meta', {}).get('versionId')
        if not isinstance(rid, str) or not rid or not isinstance(version, str) or not version:
            raise IntegrationError('Cada recurso deve ter id e meta.versionId de origem.')
        subject = resource.get('patient' if kind == 'AllergyIntolerance' else 'subject', {}).get('reference')
        if subject not in SOURCES[source]:
            raise IntegrationError('Identificação não corresponde ao paciente sintético autorizado. Importação bloqueada.')
        key = f'{source}|{kind}|{rid}|{version}'
        if key in seen:
            raise IntegrationError('Recurso repetido dentro do lote.')
        seen.add(key)
        code = resource.get('code', {})
        item = dict(key=key, source=source, patient_id=PATIENT, resource_type=kind,
                    source_id=rid, source_version=version, content_hash=digest(resource),
                    title=label(code), status=resource.get('status', 'não informado'),
                    event_date=resource.get('effectiveDateTime') or resource.get('performedDateTime')
                    or resource.get('onsetDateTime') or resource.get('period', {}).get('start'),
                    issued=resource.get('issued'), code=code, original=resource,
                    review_status='pendente de revisão profissional')
        if kind == 'Observation':
            item.update(value=resource.get('valueQuantity'), text_value=resource.get('valueString'),
                        reference_ranges=resource.get('referenceRange', []),
                        method=resource.get('method'), specimen=resource.get('specimen'))
        if kind == 'DiagnosticReport':
            item.update(result_refs=resource.get('result', []),
                        attachments=resource.get('presentedForm', []))
        if kind == 'AllergyIntolerance':
            item.update(criticality=resource.get('criticality', 'não informada'),
                        clinical_status=resource.get('clinicalStatus'),
                        verification_status=resource.get('verificationStatus'),
                        reactions=resource.get('reaction', []))
        if kind == 'MedicationStatement':
            item['title'] = label(resource.get('medicationCodeableConcept', {}))
            item['dosage'] = resource.get('dosage', [])
        if kind == 'Encounter':
            item['title'] = 'Atendimento registrado na origem'
        results.append(item)
    # References must resolve inside this batch to the mapped patient; no URL fetching.
    observations = {f"Observation/{i['source_id']}" for i in results if i['resource_type'] == 'Observation'}
    for item in results:
        for ref in item.get('result_refs', []):
            if ref.get('reference') not in observations:
                raise IntegrationError('Resultado do laudo não resolvido neste lote.')
    return results

def apply_batch(existing, incoming):
    """Pure staging: no mutations on failure; retain previous versions."""
    staged = {r['key']: r for r in existing}
    inserted = duplicates = 0
    for row in incoming:
        old = staged.get(row['key'])
        if old:
            if old['content_hash'] != row['content_hash']:
                raise IntegrationError('Conteúdo alterado com a mesma versão: exige conferência da origem.')
            duplicates += 1
        else:
            staged[row['key']] = row
            inserted += 1
    return list(staged.values()), {'inserted': inserted, 'duplicates': duplicates}

def review_flags(rows):
    flags = []
    allergies = [r for r in rows if r['resource_type'] == 'AllergyIntolerance']
    if len({r['source'] for r in allergies}) > 1:
        flags.append('Há registros de alergia de fontes diferentes. Conferir todos; ausência de informação não significa ausência de alergia.')
    versions = {}
    for row in rows:
        key = (row['source'], row['resource_type'], row['source_id'])
        versions.setdefault(key, set()).add(row['source_version'])
    if any(len(v) > 1 for v in versions.values()):
        flags.append('Há versões diferentes do mesmo registro. As versões anteriores foram preservadas; conferir a correção na origem.')
    obs = [r for r in rows if r['resource_type'] == 'Observation']
    if len({json.dumps((r.get('value', {}).get('unit') if r.get('value') else None, r.get('method')), sort_keys=True) for r in obs}) > 1:
        flags.append('Resultados com unidades ou métodos diferentes permanecem separados, sem conversão nem comparação automática.')
    return flags

if __name__ == '__main__':
    from pathlib import Path
    root = Path(__file__).parent
    rows = []
    for source in SOURCES:
        payload = json.loads((root / f'{source}.json').read_text(encoding='utf-8'))
        rows, _ = apply_batch(rows, normalize(source, payload))
    print(json.dumps({'patient_id': PATIENT, 'records': rows, 'flags': review_flags(rows)}, ensure_ascii=False, indent=2))
