import ast,uuid,pathlib,json
source=pathlib.Path('portal.py').read_text(encoding='utf-8');tree=ast.parse(source);ns={'uuid':uuid,'_REALITY_DATA':None}
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('reality_uuid_for_user','reality_registry','reality_clients')],type_ignores=[]),'portal','exec'),ns)
data={'users':{'old':{},'disabled':{'status':'disabled'}}};reg=ns['reality_registry'](data);old=reg['old'];assert old==str(uuid.uuid5(uuid.NAMESPACE_URL,'hy2-portal-reality:old'))
data['users']['new']={};ns['reality_registry'](data);new=reg['new'];assert uuid.UUID(new).version==4 and new!=str(uuid.uuid5(uuid.NAMESPACE_URL,'hy2-portal-reality:new'))
assert ns['reality_uuid_for_user']('new')==new
assert all(x['email']!='disabled' for x in ns['reality_clients'](data))
ns['reality_registry'](json.loads(json.dumps(data)));assert ns['reality_uuid_for_user']('new')==new
print('REALITY_REGISTRY_TESTS_OK')
