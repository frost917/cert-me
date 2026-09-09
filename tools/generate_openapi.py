#!/usr/bin/env python3
"""Build the initial OpenAPI contract. Handlers are not implemented by this file."""
import copy
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def ref(n):return {'$ref':'#/components/schemas/'+n}
def obj(p,required=()):return {'type':'object','additionalProperties':False,'properties':p,**({'required':list(required)} if required else {})}
def string(**kw):return {'type':'string',**kw}
def enum(*v):return string(enum=list(v))
def arr(s):return {'type':'array','items':s}
def nullable(s):
    if '$ref' not in s: return dict(s,nullable=True)
    name=s['$ref'].rsplit('/',1)[1]
    S.setdefault('Nullable'+name,dict(copy.deepcopy(S[name]),nullable=True))
    return ref('Nullable'+name)
ID=string(format='uuid');TIME=string(format='date-time');TEXT=string(maxLength=4096);NAME=string(minLength=1,maxLength=255)
INT={'type':'integer','format':'int64','minimum':0}; BOOL={'type':'boolean'}
HEX=string(pattern='^(0|[1-9a-f][0-9a-f]{0,39})$');HASH=string(pattern='^[0-9a-f]{64}$')
PASS=string(minLength=12,maxLength=128,writeOnly=True)
TOKEN=string(minLength=32,maxLength=256,writeOnly=True)
VERSION={'type':'integer','format':'int64','minimum':0}
KEY=enum('ecdsa_p256','ecdsa_p384','rsa_2048','rsa_3072','rsa_4096')
REASON=enum('unspecified','keyCompromise','caCompromise','affiliationChanged','superseded','cessationOfOperation','privilegeWithdrawn','aACompromise')
SNAP={'type':'object','required':['schema_version'],'properties':{'schema_version':{'type':'integer','minimum':1}},'additionalProperties':True,'description':'버전별 공개 메타데이터. 개인키·토큰·해제 암호 금지.'}
S={}
S['Error']=obj({'error':obj({'code':string(),'message':string(),'request_id':string(),'fields':{'type':'object','additionalProperties':string()}},['code','message','request_id'])},['error'])
S['Validity']=obj({'value':{'type':'integer','minimum':1,'maximum':36500},'unit':enum('years','months','days')},['value','unit'])
S['Subject']=obj({'common_name':NAME,'organization':NAME,'organizational_unit':NAME,'country':string(pattern='^[A-Z]{2}$')},['common_name'])
S['SAN']=obj({'type':enum('dns','ip','uri'),'value':string(minLength=1,maxLength=2048)},['type','value'])
S['Credentials']=obj({'login_name':string(pattern='^[A-Za-z0-9._-]{3,64}$'),'password':PASS},['login_name','password'])
S['PasswordReset']=obj({'reset_token':TOKEN,'new_password':PASS},['reset_token','new_password'])
S['Account']=obj({'id':ID,'login_name':NAME,'state':enum('active','reset_pending','disabled'),'is_global_admin':BOOL,'version':VERSION},['id','login_name','state','is_global_admin','version'])
S['Setup']=obj({'setup_stage':enum('account_required','pki_required','complete'),'bootstrap_https':BOOL},['setup_stage','bootstrap_https'])
S['CSRF']=obj({'csrf_token':string(minLength=32,maxLength=256)},['csrf_token'])
S['Session']=obj({'account':ref('Account'),'idle_expires_at':TIME,'absolute_expires_at':TIME},['account','idle_expires_at','absolute_expires_at'])
S['Login']=obj({**S['Session']['properties'],'csrf_token':string(minLength=32,maxLength=256)},['account','csrf_token','idle_expires_at','absolute_expires_at'])
settings={'service_url':string(format='uri',pattern='^https://'),'leaf_validity':ref('Validity'),'root_validity':ref('Validity'),'intermediate_validity':ref('Validity'),'rotate_every':{'type':'integer','minimum':1,'maximum':100,'default':3},'private_delivery_seconds':{'type':'integer','minimum':300,'maximum':86400,'default':10800},'public_link_seconds':{'type':'integer','minimum':60,'maximum':10800,'default':600},'crl_interval_seconds':{'type':'integer','minimum':300,'maximum':86400,'default':43200},'crl_validity_seconds':{'type':'integer','minimum':600,'maximum':604800,'default':172800},'audit_retention_days':{'type':'integer','minimum':30,'maximum':3650,'default':365}}
S['SettingsPatch']=obj(settings);S['SettingsPatch']['minProperties']=1
S['Settings']=obj({**settings,'version':VERSION},list(settings)+['version']);S['Settings']['description']='CRL validity must be at least twice interval; URL must match active operational TLS certificate or be changed through CLI recovery.'
S['NamePatch']=obj({'name':NAME},['name'])
S['LeafPatch']=obj({'name':NAME,'validity':ref('Validity'),'rotate_every':settings['rotate_every']});S['LeafPatch']['minProperties']=1
S['AuthorityCreate']=obj({'kind':enum('root','intermediate'),'name':NAME,'parent_authority_id':ID,'subject':ref('Subject'),'key_algorithm':KEY,'validity':ref('Validity')},['kind','name','subject'])
S['AuthorityCreate']['description']='intermediate requires parent_authority_id; root forbids it. Defaults: P-256, root 10 years, intermediate 5 years.'
S['CRLStatus']=obj({'number_hex':nullable(HEX),'covered_generation':nullable(INT),'revocation_generation':INT,'next_publish_at':nullable(TIME),'next_update':nullable(TIME),'publication_state':enum('inactive','active','closed'),'pending':BOOL,'expired':BOOL,'last_error_code':nullable(string()),'version':VERSION},['revocation_generation','publication_state','pending','expired','version'])
S['Authority']=obj({'id':ID,'kind':enum('root','intermediate'),'name':NAME,'management_parent_id':nullable(ID),'issuance_state':enum('inventory','enabled','stopped'),'issuance_certificate_id':nullable(ID),'key_generation_id':ID,'key_available':BOOL,'affected':BOOL,'not_after':TIME,'archived_at':nullable(TIME),'crl':ref('CRLStatus'),'version':VERSION,'created_at':TIME},['id','kind','name','issuance_state','key_generation_id','key_available','affected','version','created_at'])
leafInput={'name':NAME,'authority_id':ID,'profile':enum('server_tls','client_mtls','dual'),'subject':ref('Subject'),'sans':{'type':'array','maxItems':100,'items':ref('SAN')},'key_algorithm':KEY,'validity':ref('Validity'),'rotate_every':settings['rotate_every']}
S['LeafCreate']=obj(leafInput,['name','authority_id','profile','subject']);S['LeafCreate']['description']='server_tls/dual require at least one DNS or IP SAN. Defaults: P-256, 1 year, rotate every 3 renewals.'
S['Renew']=obj({'source_certificate_id':ID,'target_authority_id':ID,'transition_id':ID},['source_certificate_id'])
S['Reissue']=obj({**S['Renew']['properties'],'reason':enum('delivery_failed','delivery_expired','key_compromise','manual_rotation','emergency')},['source_certificate_id','reason'])
S['Delivery']=obj({'id':ID,'certificate_id':ID,'state':enum('pending','transferring','server_completed','failed','expired'),'expires_at':TIME,'consumed_at':nullable(TIME),'finished_at':nullable(TIME),'failure_code':nullable(string()),'version':VERSION},['id','certificate_id','state','expires_at','version'])
S['Issuance']=obj({'series_id':ID,'certificate_id':ID,'key_generation_id':ID,'renewal_count':INT,'key_rotated':BOOL,'delivery':nullable(ref('Delivery')),'certificate_url':string(format='uri-reference'),'series_url':string(format='uri-reference')},['series_id','certificate_id','key_generation_id','renewal_count','key_rotated','delivery'])
S['LeafSeries']=obj({'id':ID,'name':NAME,'purpose':enum('distributed','internal_tls','bootstrap_tls'),'management_authority_id':ID,'current_certificate_id':nullable(ID),'current_key_generation_id':nullable(ID),'validity':ref('Validity'),'rotate_every':settings['rotate_every'],'renewal_count':INT,'prior_history_unknown':BOOL,'delivery':nullable(ref('Delivery')),'archived_at':nullable(TIME),'version':VERSION,'created_at':TIME},['id','name','purpose','management_authority_id','version','created_at'])
S['Certificate']=obj({'id':ID,'der_sha256':HASH,'key_material_id':ID,'issuer_ca_key_generation_id':ID,'serial_hex':HEX,'not_before':TIME,'not_after':TIME,'subject':ref('Subject'),'sans':arr(ref('SAN')),'origin':enum('generated','imported'),'series_id':nullable(ID),'revoked':BOOL,'affected':BOOL,'expired':BOOL,'delivery':nullable(ref('Delivery')),'created_at':TIME},['id','der_sha256','key_material_id','issuer_ca_key_generation_id','serial_hex','not_before','not_after','revoked','affected','expired','created_at'])
S['Justification']=obj({'justification':string(minLength=1,maxLength=4096)},['justification'])
S['Revoke']=obj({'reason':REASON,'justification':TEXT},['reason','justification'])
S['RevocationCorrection']=obj({'revoked_at':TIME,**S['Revoke']['properties']},['revoked_at','reason','justification'])
S['Revocation']=obj({'id':ID,'issuer_ca_key_generation_id':ID,'serial_hex':HEX,'certificate_id':nullable(ID),'revoked_at':TIME,'reason':REASON,'source':string(),'change_generation':INT,'crl_pending':BOOL,'version':VERSION,'created_at':TIME},['id','issuer_ca_key_generation_id','serial_hex','revoked_at','reason','change_generation','crl_pending','version'])
S['Compromise']=obj({'key_material_id':ID,'compromised_at':TIME,'revocations':arr(ref('Revocation'))},['key_material_id','compromised_at','revocations'])
S['DeliveryFailure']=obj({'delivery':ref('Delivery'),'revocation':ref('Revocation')},['delivery','revocation'])
S['IssuanceState']=obj({'state':enum('enabled','stopped')},['state'])
S['KeyDestruction']=obj({'key_generation_id':ID,'justification':TEXT},['key_generation_id','justification'])
S['DownloadLinkRequest']=obj({'purpose':enum('public','private')},['purpose'])
S['DownloadLink']=obj({'url':string(format='uri'),'expires_at':TIME,'token_id':ID},['url','expires_at','token_id'])
S['Job']=obj({'id':ID,'kind':string(),'state':enum('pending','running','succeeded','failed'),'last_error_code':nullable(string()),'available_at':TIME,'attempt_count':INT,'version':VERSION},['id','kind','state','version'])
S['JobAccepted']=obj({'job_id':ID},['job_id'])
S['TakeoverInput']=obj({'history_assertion':enum('crls_provided','no_previous_revocations'),'previous_max_number_hex':HEX,'external_issuer_stopped_at':TIME,'evidence':SNAP},['history_assertion','previous_max_number_hex','external_issuer_stopped_at','evidence'])
S['Takeover']=obj({'id':ID,'ca_key_generation_id':ID,'state':enum('pending','confirmed'),'confirmed_at':nullable(TIME),'version':VERSION},['id','ca_key_generation_id','state','version'])
S['ImportItem']=obj({'file_id':string(maxLength=128),'sha256':HASH,'kind':enum('certificate','crl','ca_key'),'status':enum('new','duplicate','conflict'),'existing_id':nullable(ID),'error_code':nullable(string())},['file_id','kind','status'])
S['ImportPreview']=obj({'manifest':SNAP,'items':arr(ref('ImportItem'))},['manifest','items'])
S['ImportResult']=obj({'id':ID,'state':enum('committed','failed'),'committed_at':nullable(TIME),'items':arr(ref('ImportItem')),'certificate_ids':arr(ID),'authority_ids':arr(ID)},['id','state','items','certificate_ids','authority_ids'])
# Binary multipart parts are bounded independently by handler; never disk-spool key parts.
BINARY=string(format='binary',writeOnly=True)
S['ImportUpload']=obj({'files':{'type':'array','maxItems':100,'minItems':1,'items':BINARY},'metadata':SNAP},['files','metadata'])
S['ImportUpload']['description']='metadata maps multipart file names to certificate/crl/ca_key, issuer certificate IDs and key passphrases; metadata is request-only and secret fields must not be persisted. Total 16 MiB, each file 4 MiB.'
# Give metadata a concrete wire shape instead of arbitrary secret-bearing JSON.
S['ImportFileMetadata']=obj({'file_name':string(minLength=1,maxLength=128),'kind':enum('certificate','crl','ca_key'),'issuer_certificate_id':ID,'passphrase':string(writeOnly=True,maxLength=4096)},['file_name','kind'])
S['ImportMetadata']=obj({'schema_version':{'type':'integer','enum':[1]},'files':arr(ref('ImportFileMetadata')),'preview_manifest':SNAP,'takeovers':arr(obj({'ca_certificate_sha256':HASH,'confirmation':ref('TakeoverInput')},['ca_certificate_sha256','confirmation']))},['schema_version','files'])
S['ImportUpload']['properties']['metadata']=ref('ImportMetadata')
S['SigningKeyUpload']=obj({'key':BINARY,'passphrase':string(writeOnly=True,maxLength=4096)},['key'])
S['TLSUpload']=obj({'certificate':BINARY,'chain':BINARY,'key':BINARY,'passphrase':string(writeOnly=True,maxLength=4096)},['certificate','key'])
S['TLSIssue']=obj({k:v for k,v in leafInput.items() if k not in ('name','profile','rotate_every')},['authority_id','subject','sans'])
S['TLSVersion']=obj({'id':ID,'source':enum('bootstrap','managed','external'),'certificate_id':nullable(ID),'not_after':TIME,'validated_service_url':nullable(string(format='uri'))},['id','source','not_after'])
S['TLSStatus']=obj({'active':nullable(ref('TLSVersion')),'phase':nullable(enum('prepared','committed','applied','rolled_back','recovery_required')),'candidate_id':nullable(ID),'error_code':nullable(string()),'version':VERSION},['active','version'])
S['TLSActivation']=obj({'candidate_id':ID},['candidate_id'])
S['TransitionCreate']=obj({'source_authority_id':ID,'target_authority_id':ID,'mode':enum('normal','emergency'),'reason':TEXT},['source_authority_id','mode','reason'])
S['TransitionPatch']=obj({'target_authority_id':ID},['target_authority_id'])
S['Impact']=obj({'certificate_id':ID,'replacement_certificate_id':nullable(ID),'reissued_at':nullable(TIME)},['certificate_id'])
S['Transition']=obj({'id':ID,'source_authority_id':ID,'target_authority_id':nullable(ID),'mode':enum('normal','emergency'),'state':enum('in_progress','externally_completed','closed'),'external_transition_complete':BOOL,'ca_publication_closed':BOOL,'impacts':arr(ref('Impact')),'version':VERSION,'created_at':TIME},['id','source_authority_id','mode','state','version','created_at'])
S['DeploymentInput']=obj({'target_label':NAME,'certificate_id':ID,'action':enum('trust_added','certificate_installed','trust_removed')},['target_label','action'])
S['Deployment']=obj({'id':ID,**S['DeploymentInput']['properties'],'confirmed_at':TIME,'confirmed_by':ID},['id','target_label','action','confirmed_at','confirmed_by'])
S['AuditEvent']=obj({'id':ID,'occurred_at':TIME,'actor_kind':enum('account','download_token','cli','system','anonymous'),'actor_id':nullable(ID),'token_id':nullable(ID),'action':string(),'target_type':string(),'target_id':nullable(ID),'client_ip':nullable(string()),'result':enum('success','failure'),'details':SNAP,'authority_ids':arr(ID)},['id','occurred_at','actor_kind','action','result','authority_ids'])
S['Empty']=obj({})

P={}
for name,header,schema in [('CSRF','X-CSRF-Token',string(minLength=32,maxLength=256)),('IfMatch','If-Match',string(pattern='^"v[0-9]+"$')),('Idempotency','Idempotency-Key',ID)]:
 P[name]={'name':header,'in':'header','required':True,'schema':schema}

def param(name,schema,where='query',required=False):return {'name':name,'in':where,'required':required,'schema':schema}
def pref(n):return {'$ref':'#/components/parameters/'+n}
HEADERS={'Cache-Control':{'schema':string(),'description':'no-store for management and token responses'}}
ERRORS={str(c):{'description':desc,'content':{'application/json':{'schema':ref('Error')}}} for c,desc in [(400,'Malformed request'),(401,'Authentication required'),(403,'Permission or CSRF rejected'),(404,'Not found or download unavailable'),(409,'State or idempotency conflict'),(412,'Version mismatch'),(413,'Payload too large'),(422,'Policy validation failed'),(428,'Required precondition missing'),(429,'Rate limited'),(503,'Unavailable or maintenance')]}
ERRORS['429']['headers']={'Retry-After':{'schema':string()}}
paths={}; operations=[]
def endpoint(method,path,operation,out=None,body=None,status=200,public=False,match=False,idem=False,listing=False,multipart=False,description=None):
 full=path if path.startswith(('/download','/pki','/reset-password')) else '/api/v1'+path
 ps=[]
 if '{id}' in full:ps.append(param('id',ID,'path',True))
 if '{token}' in full:ps.append(param('token',string(minLength=32,maxLength=256),'path',True))
 if method not in ('get','head'):ps.append(pref('CSRF'))
 if match:ps.append(pref('IfMatch'))
 if idem:ps.append(pref('Idempotency'))
 if listing:ps += [param('cursor',string()),param('limit',{'type':'integer','minimum':1,'maximum':200,'default':50}),param('q',string(maxLength=255))]
 op={'operationId':operation,'summary':operation,'tags':[path.strip('/').split('/')[0]],'parameters':ps,'responses':{code:{'$ref':'#/components/responses/Error'+code} for code in ERRORS}}
 if public:op['security']=[]
 if description:op['description']=description
 success={'description':'Success','headers':copy.deepcopy(HEADERS)}
 if out:
  data=ref(out)
  if listing:data=obj({'data':arr(data),'next_cursor':nullable(string())},['data','next_cursor'])
  else:data=obj({'data':data},['data'])
  success['content']={'application/json':{'schema':data}}
 if out and out in ['Authority','LeafSeries','Settings','Session','Delivery','Transition','TLSStatus','Revocation','Takeover','Job']:
  success['headers']['ETag']={'schema':string(pattern='^"v[0-9]+"$')}
 op['responses'][str(status)]=success
 if idem and status==201:op['responses']['200']=dict(success,description='Replay of the existing result; no key or token secret is returned')
 if body:
  media='multipart/form-data' if multipart else 'application/json'
  op['requestBody']={'required':True,'content':{media:{'schema':ref(body)}}}
  if body=='ImportUpload':op['requestBody']['content'][media]['encoding']={'metadata':{'contentType':'application/json'}}
 paths.setdefault(full,{})[method]=op;operations.append(operation)
 return op

endpoint('get','/setup','getSetup','Setup',public=True)
endpoint('get','/auth/csrf','getCSRF','CSRF',public=True,description='Same-origin only; may use current session or pre-auth nonce cookie. Never grants setup authorization.')
endpoint('post','/setup/admin','createFirstAdmin','Account','Credentials',201,public=True)
login=endpoint('post','/auth/login','login','Login','Credentials',public=True)
login['responses']['200']['headers']['Set-Cookie']={'schema':string(),'description':'__Host-certme_session; Secure; HttpOnly; SameSite=Strict; Path=/'}
endpoint('post','/auth/logout','logout',status=204)
endpoint('get','/auth/me','getSession','Session')
endpoint('post','/auth/password-reset','completePasswordReset',body='PasswordReset',status=204,public=True)
endpoint('get','/settings','getSettings','Settings')
endpoint('patch','/settings','updateSettings','Settings','SettingsPatch',match=True)
endpoint('post','/setup/complete','completeSetup','Setup','Empty',match=True)
endpoint('get','/authorities','listAuthorities','Authority',listing=True)
endpoint('post','/authorities','createAuthority','Authority','AuthorityCreate',201,idem=True)
endpoint('get','/authorities/{id}','getAuthority','Authority')
endpoint('patch','/authorities/{id}','renameAuthority','Authority','NamePatch',match=True)
for suffix,body in [('issuance-state','IssuanceState'),('key-destruction','KeyDestruction'),('archive','Empty')]:endpoint('post','/authorities/{id}/'+suffix,'authority'+suffix.title().replace('-',''),'Authority',body,match=True)
endpoint('get','/leaf-series','listLeafSeries','LeafSeries',listing=True)
endpoint('post','/leaf-series','issueLeaf','Issuance','LeafCreate',201,idem=True)
endpoint('get','/leaf-series/{id}','getLeafSeries','LeafSeries')
endpoint('patch','/leaf-series/{id}','updateLeafSeries','LeafSeries','LeafPatch',match=True)
for suffix,body in [('renewals','Renew'),('reissues','Reissue')]:endpoint('post','/leaf-series/{id}/'+suffix,suffix+'Leaf','Issuance',body,201,match=True,idem=True)
endpoint('post','/leaf-series/{id}/archive','archiveLeafSeries','LeafSeries','Empty',match=True)
endpoint('get','/certificates','listCertificates','Certificate',listing=True)
endpoint('get','/certificates/{id}','getCertificate','Certificate')
endpoint('post','/certificates/{id}/revocations','revokeCertificate','Revocation','Revoke')
endpoint('post','/key-materials/{id}/compromise','reportKeyCompromise','Compromise','Justification')
endpoint('post','/key-deliveries/{id}/failure','reportDeliveryFailure','DeliveryFailure','Justification',match=True)
endpoint('get','/revocations','listRevocations','Revocation',listing=True)
endpoint('post','/revocations/{id}/corrections','correctRevocation','Revocation','RevocationCorrection',match=True)
endpoint('get','/authorities/{id}/crl','getCRLStatus','CRLStatus')
endpoint('post','/authorities/{id}/crl-publications','requestCRLPublication','JobAccepted','Empty',202)
endpoint('get','/jobs/{id}','getJob','Job')
endpoint('post','/certificates/{id}/download-links','createDownloadLink','DownloadLink','DownloadLinkRequest',201)
endpoint('post','/imports/previews','previewImport','ImportPreview','ImportUpload',multipart=True)
endpoint('post','/imports','commitImport','ImportResult','ImportUpload',201,idem=True,multipart=True,description='Resubmit original files. Validate current DB and preview_manifest again; no plaintext keys or passwords persist.')
endpoint('get','/imports/{id}','getImport','ImportResult')
endpoint('post','/authorities/{id}/signing-key','attachSigningKey','Authority','SigningKeyUpload',match=True,multipart=True)
endpoint('post','/authorities/{id}/takeover','confirmTakeover','Takeover','TakeoverInput',match=True)
endpoint('get','/transitions','listTransitions','Transition',listing=True)
endpoint('post','/transitions','createTransition','Transition','TransitionCreate',201,description='Emergency creation atomically stops affected issuers; target may be assigned later.')
endpoint('get','/transitions/{id}','getTransition','Transition')
endpoint('patch','/transitions/{id}','setTransitionTarget','Transition','TransitionPatch',match=True)
endpoint('post','/transitions/{id}/deployment-confirmations','confirmDeployment','Deployment','DeploymentInput',201,match=True)
endpoint('post','/transitions/{id}/complete','completeTransition','Transition','Empty',match=True)
endpoint('get','/tls','getTLS','TLSStatus')
endpoint('post','/tls/candidates','uploadTLSCandidate','TLSVersion','TLSUpload',201,multipart=True)
endpoint('post','/tls/issuances','issueTLSCandidate','TLSVersion','TLSIssue',201,idem=True)
endpoint('post','/tls/reloads','reloadTLSCandidate','TLSVersion','Empty',201)
endpoint('post','/tls/activations','activateTLS','TLSStatus','TLSActivation',match=True)
endpoint('get','/audit-events','listAuditEvents','AuditEvent',listing=True)
export=endpoint('get','/audit-events/export','exportAudit')
export['parameters'].append(param('format',enum('json','csv'),required=True))
export['responses']['200']['content']={'application/json':{'schema':arr(ref('AuditEvent'))},'text/csv':{'schema':string(format='binary')}}
for path in ['/api/v1/certificates','/api/v1/leaf-series','/api/v1/revocations']:
 paths[path]['get']['parameters'].append(param('authority_id',ID))
paths['/api/v1/certificates']['get']['parameters'] += [param('expires_before',TIME),param('revoked',BOOL),param('affected',BOOL)]
paths['/api/v1/revocations']['get']['parameters'].append(param('serial_hex',HEX))
for path in ['/api/v1/audit-events','/api/v1/audit-events/export']:
 paths[path]['get']['parameters'] += [param(n,s) for n,s in [('from',TIME),('until',TIME),('account_id',ID),('authority_id',ID),('certificate_id',ID),('action',string()),('client_ip',string()),('result',enum('success','failure'))]]
get=endpoint('get','/download/{token}','downloadOnce',public=True,description='Only a valid GET consumes the capability. Build payload before atomic consumption and deletion. No resume. Invalid/expired/consumed tokens all return 404. Never log the token or PKCS12 password. A private capability only permits private-key PEM, private ZIP or PKCS12; public capability only permits public PEM/ZIP.')
get['parameters'] += [param('format',enum('pem','zip','pkcs12'),required=True),param('part',enum('certificate','chain','private_key')),param('X-CertMe-PKCS12-Password',string(writeOnly=True,maxLength=4096),'header')]
get['responses']['200']['content']={m:{'schema':string(format='binary')} for m in ['application/x-pem-file','application/zip','application/pkcs12']}
get['responses']['200']['headers']['Referrer-Policy']={'schema':string(enum=['no-referrer'])}
get['responses']['200']['headers']['Content-Disposition']={'schema':string()}
head=endpoint('head','/download/{token}','rejectDownloadHead',public=True,status=405)
head['responses']={'405':{'description':'No file and no token consumption','headers':{'Allow':{'schema':string(enum=['GET'])}}}}
for suffix,operation,media in [('certificate.pem','getCACertificate','application/x-pem-file'),('chain.pem','getCAChain','application/x-pem-file'),('crl.der','getPublicCRL','application/pkix-crl')]:
 op=endpoint('get','/pki/ca-certificates/{id}/'+suffix,operation,public=True)
 op['responses']['200']={'description':'Immutable certificate/chain or latest CRL; expired final CRL remains retrievable','content':{media:{'schema':string(format='binary')}},'headers':{'ETag':{'schema':string()},'Cache-Control':{'schema':string()}}}
 op['parameters'].append(param('If-None-Match',string(),'header'))
 op['responses']['304']={'description':'Not modified'}
reset=endpoint('get','/reset-password/{token}','getPasswordResetPage',public=True)
reset['responses']['200']['content']={'text/html':{'schema':string()}}
reset['description']='Renders reset form only. Does not consume token or log in; no-store and no-referrer.'
reset['responses']['200']['headers']['Referrer-Policy']={'schema':string(enum=['no-referrer'])}
assert len(operations)==len(set(operations))
spec={'openapi':'3.0.3','info':{'title':'cert-me API','version':'0.1.0','description':'MVP contract, not a deployed service. Session + CSRF for administration; purpose-bound one-use download links. Cross-field PKI policy is validated by the service.'},'servers':[{'url':'/'}],'security':[{'SessionCookie':[]}],'paths':paths,'components':{'securitySchemes':{'SessionCookie':{'type':'apiKey','in':'cookie','name':'__Host-certme_session'}},'parameters':P,'responses':{'Error'+code:value for code,value in ERRORS.items()},'schemas':S}}
(ROOT/'api/openapi.json').write_text(json.dumps(spec,ensure_ascii=False,indent=2)+'\n')
print(len(paths),'paths,',len(operations),'operations,',len(S),'schemas')
