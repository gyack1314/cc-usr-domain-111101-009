from datapack.domain import framed,normalize,unknown_fields,reference_gaps
def check(case):
    case.assertNotEqual(framed(['ab','c']),framed(['a','bc']))
    case.assertEqual(normalize('v-1','upper_ascii'),'V-1')
    with case.assertRaises(ValueError):normalize('甲','upper_ascii')
    case.assertEqual(unknown_fields([{'a':1,'b':2}],{'fields':{'a':{}}}),['b'])
    case.assertEqual(reference_gaps([{'f':'x'},{'f':'y'}],'f',['x']),[1])
