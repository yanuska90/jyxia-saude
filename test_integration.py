import copy
import json
import unittest
from pathlib import Path
from integration import normalize, apply_batch, IntegrationError, review_flags

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.bundle=json.loads((Path(__file__).parent/'lab-demo.json').read_text(encoding='utf-8'))
    def test_two_sources_same_internal_patient(self):
        hospital=json.loads((Path(__file__).parent/'hospital-demo.json').read_text(encoding='utf-8'))
        rows=normalize('lab-demo',self.bundle)+normalize('hospital-demo',hospital)
        self.assertEqual({r['patient_id'] for r in rows},{'SYN-P01'})
        self.assertEqual(len(rows),7)
    def test_wrong_patient_rejected(self):
        self.bundle['entry'][0]['resource']['subject']['reference']='Patient/WRONG'
        with self.assertRaises(IntegrationError):normalize('lab-demo',self.bundle)
    def test_unknown_source_rejected(self):
        with self.assertRaises(IntegrationError):normalize('unknown',self.bundle)
    def test_repeat_is_idempotent(self):
        rows=normalize('lab-demo',self.bundle)
        result,stats=apply_batch(rows,rows)
        self.assertEqual(len(result),2)
        self.assertEqual(stats,{'inserted':0,'duplicates':2})
    def test_same_version_changed_content_rejected_without_mutation(self):
        rows=normalize('lab-demo',self.bundle)
        before=copy.deepcopy(rows)
        self.bundle['entry'][0]['resource']['valueQuantity']['value']=99
        with self.assertRaises(IntegrationError):apply_batch(rows,normalize('lab-demo',self.bundle))
        self.assertEqual(rows,before)
    def test_new_version_preserves_old(self):
        rows=normalize('lab-demo',self.bundle)
        self.bundle['entry'][0]['resource']['meta']['versionId']='2'
        self.bundle['entry'][0]['resource']['valueQuantity']['value']=11
        result,stats=apply_batch(rows,normalize('lab-demo',self.bundle))
        self.assertEqual(len(result),3)
        self.assertEqual(stats,{'inserted':1,'duplicates':1})
        self.assertTrue(review_flags(result))
    def test_unresolved_report_rejected(self):
        self.bundle['entry'][1]['resource']['result'][0]['reference']='Observation/missing'
        with self.assertRaises(IntegrationError):normalize('lab-demo',self.bundle)
    def test_source_preserved(self):
        row=normalize('lab-demo',self.bundle)[0]
        self.assertEqual(row['original'],self.bundle['entry'][0]['resource'])
        self.assertEqual(row['reference_ranges'][0]['text'],'Intervalo fictício 8 a 12')
        self.assertEqual(row['value']['unit'],'unidade de teste A')
    def test_unsupported_type_rejected(self):
        self.bundle['entry'][0]['resource']['resourceType']='Patient'
        with self.assertRaises(IntegrationError):normalize('lab-demo',self.bundle)
    def test_ambiguous_composite_identifier_rejected(self):
        self.bundle['entry'][0]['resource']['id']='obs|01'
        with self.assertRaises(IntegrationError):normalize('lab-demo',self.bundle)
    def test_invalid_quantity_rejected_before_persistence(self):
        self.bundle['entry'][0]['resource']['valueQuantity']=['invalid']
        with self.assertRaises(IntegrationError):normalize('lab-demo',self.bundle)

if __name__=='__main__':unittest.main()
