import struct
def framed(parts):
    out=b''
    for part in parts:
        data=part.encode('utf-8');out+=struct.pack('>I',len(data))+data
    return out
def normalize(value,rule):
    if not isinstance(value,str):raise ValueError('ID_TYPE')
    if rule=='exact':return value
    if rule=='strip':return value.strip()
    if rule=='upper_ascii':
        if not value.isascii():raise ValueError('ID_CHARSET')
        return value.upper()
    raise ValueError('NORMALIZER_UNKNOWN')
def unknown_fields(rows,policy):
    return sorted({key for row in rows for key in row if key not in policy['fields']})
def reference_gaps(rows,field,target_values):
    known=set(target_values)
    return [i for i,row in enumerate(rows) if row.get(field) not in known]
