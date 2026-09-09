#!/usr/bin/env python3
"""Generate the unreleased initial schema. Released migrations must never be regenerated."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# name:type[?][@table.column]; missing FK column means id.
# Common rows have id/created_at; mutable rows additionally have updated_at/version.
TABLES = []
def table(group, name, fields, *, pk='id', unique=(), checks=(), mutable=False, common=True):
    columns = []
    if common:
        columns += [('id','uuid',False,None), ('created_at','int',False,None)]
    if mutable:
        columns += [('updated_at','int',False,None), ('version','counter',False,None)]
    for field in fields.split():
        n, spec = field.split(':',1)
        typ, _, fk = spec.partition('@')
        nullable = typ.endswith('?'); typ=typ.rstrip('?')
        columns.append((n,typ,nullable,fk or None))
    TABLES.append(dict(group=group,name=name,columns=columns,pk=pk.split(','),unique=[u.split(',') for u in unique],checks=list(checks)))

table(0,'schema_migrations','version:int name:a128 checksum:hash state:a32 started_at:int completed_at:int? last_step:counter error_code:a64?',pk='version',common=False,checks=["state IN ('applying','applied','failed')"])
table(1,'accounts','login_name:a64 normalized_login_name:a64 password_hash:text state:a32 auth_epoch:counter is_global_admin:bool',unique=['normalized_login_name'],mutable=True,checks=["state IN ('active','reset_pending','disabled')"])
table(1,'sessions','token_hash:hash account_id:uuid@accounts auth_epoch:counter last_seen_at:int absolute_expires_at:int csrf_secret_hash:hash',unique=['token_hash'])
table(1,'password_reset_tokens','token_hash:hash account_id:uuid@accounts auth_epoch:counter expires_at:int consumed_at:int? invalidated_at:int?',unique=['token_hash'])
table(1,'auth_rate_limits','kind:a32 subject_hash:hash window_start:int failure_count:counter blocked_until:int?',unique=['kind,subject_hash,window_start'])
table(1,'service_settings','id:int schema_version:counter settings_json:text updated_at:int version:counter updated_by:uuid?@accounts',common=False,checks=['id = 1'])
table(2,'key_materials','spki_sha256:hash spki_der:blob algorithm:a32 parameters_json:text origin:a32 compromised_at:int?',unique=['spki_sha256'],checks=["origin IN ('generated','imported')"])
table(2,'encryption_generations','activated_at:int retired_at:int?')
table(2,'private_key_secrets','key_material_id:uuid@key_materials purpose:a32 encryption_generation_id:uuid@encryption_generations format_version:counter nonce:blob ciphertext:blob',common=False,pk='key_material_id',checks=["purpose IN ('ca_signing','leaf_delivery','internal_tls','bootstrap_ca')",'length(nonce) = 12'])
table(2,'encryption_verifier','id:int encryption_generation_id:uuid@encryption_generations format_version:counter nonce:blob ciphertext:blob',common=False,checks=['id = 1','length(nonce) = 12'])
table(3,'authorities','kind:a32 name:text management_parent_id:uuid?@authorities issuance_state:a32 issuance_certificate_id:uuid?@ca_certificates.certificate_id archived_at:int?',mutable=True,checks=["kind IN ('root','intermediate','bootstrap')","issuance_state IN ('inventory','enabled','stopped')","(kind = 'intermediate' AND management_parent_id IS NOT NULL) OR (kind IN ('root','bootstrap') AND management_parent_id IS NULL)"])
table(3,'ca_key_generations','authority_id:uuid@authorities key_material_id:uuid@key_materials generation_no:counter key_destroyed_at:int?',unique=['authority_id,generation_no','key_material_id'])
table(3,'certificates','der_sha256:hash der:blob key_material_id:uuid@key_materials issuer_ca_key_generation_id:uuid@ca_key_generations serial_hex:hex not_before:int not_after:int subject_json:text extensions_json:text origin:a32 created_by:uuid?@accounts',unique=['der_sha256','issuer_ca_key_generation_id,serial_hex'],checks=['not_after > not_before',"serial_hex <> '0'","origin IN ('generated','imported')"])
table(3,'ca_certificates','certificate_id:uuid@certificates ca_key_generation_id:uuid@ca_key_generations issuer_ca_certificate_id:uuid?@ca_certificates.certificate_id',pk='certificate_id',common=False)
table(3,'leaf_series','name:text purpose:a32 management_authority_id:uuid@authorities current_certificate_id:uuid?@leaf_certificates.certificate_id current_key_generation_id:uuid?@leaf_key_generations validity_policy_json:text rotate_every:int archived_at:int?',mutable=True,checks=["purpose IN ('distributed','internal_tls','bootstrap_tls')",'rotate_every BETWEEN 1 AND 100'])
table(3,'leaf_key_generations','series_id:uuid@leaf_series key_material_id:uuid@key_materials generation_no:counter renewal_count:counter prior_history_unknown:bool custody:a32',unique=['series_id,generation_no'],checks=["custody IN ('pending_delivery','client_held','internal')"])
table(3,'leaf_certificates','certificate_id:uuid@certificates series_id:uuid@leaf_series leaf_key_generation_id:uuid@leaf_key_generations issuer_ca_certificate_id:uuid@ca_certificates.certificate_id previous_certificate_id:uuid?@leaf_certificates.certificate_id operation:a32 renewal_count_at_issue:counter policy_snapshot_json:text',pk='certificate_id',common=False,checks=["operation IN ('initial','renew','rekey','migrate','emergency','import')"])
table(3,'certificate_sans','certificate_id:uuid@certificates position:counter type:a32 normalized_value:text normalized_value_hash:hash',pk='certificate_id,position',common=False)
table(4,'key_deliveries','leaf_key_generation_id:uuid@leaf_key_generations certificate_id:uuid@leaf_certificates.certificate_id expires_at:int state:a32 consumed_at:int? finished_at:int? failure_code:a64?',mutable=True,unique=['leaf_key_generation_id','certificate_id'],checks=["state IN ('pending','transferring','server_completed','failed','expired')","state <> 'pending' OR consumed_at IS NULL","state NOT IN ('transferring','server_completed') OR consumed_at IS NOT NULL"])
table(4,'download_tokens','token_hash:hash purpose:a32 certificate_id:uuid@leaf_certificates.certificate_id key_delivery_id:uuid?@key_deliveries expires_at:int consumed_at:int? invalidated_at:int? created_by:uuid@accounts',unique=['token_hash'],checks=["(purpose = 'leaf_public' AND key_delivery_id IS NULL) OR (purpose = 'leaf_private' AND key_delivery_id IS NOT NULL)"])
table(4,'operation_requests','actor_key:a64 operation:a32 request_id:uuid input_hash:hash state:a32 result_certificate_id:uuid?@certificates result_json:text?',unique=['actor_key,operation,request_id'],checks=["state IN ('processing','succeeded','failed')"])
table(5,'import_batches','requested_by:uuid@accounts input_manifest_json:text state:a32 committed_at:int? result_json:text?',checks=["state IN ('previewed','committed','failed')"])
table(5,'revocations','issuer_ca_key_generation_id:uuid@ca_key_generations serial_hex:hex certificate_id:uuid?@certificates revoked_at:int reason:a32 source:a32 change_generation:counter',mutable=True,unique=['issuer_ca_key_generation_id,serial_hex'],checks=["reason IN ('unspecified','keyCompromise','caCompromise','affiliationChanged','superseded','cessationOfOperation','privilegeWithdrawn','aACompromise')"])
table(5,'revocation_revisions','revocation_id:uuid@revocations revision_no:counter previous_values_json:text new_values_json:text justification:text actor_id:uuid?@accounts source_import_id:uuid?@import_batches',unique=['revocation_id,revision_no'])
table(5,'ca_takeovers','ca_key_generation_id:uuid@ca_key_generations state:a32 history_assertion:a32 previous_max_number_hex:hex? external_issuer_stopped_at:int? confirmed_by:uuid?@accounts confirmed_at:int? evidence_json:text',mutable=True,checks=["state IN ('pending','confirmed')"])
table(5,'crl_states','ca_key_generation_id:uuid@ca_key_generations max_reserved_number_hex:hex revocation_generation:counter published_crl_id:uuid?@crl_documents next_publish_at:int? publication_state:a32 signing_ca_certificate_id:uuid?@ca_certificates.certificate_id updated_at:int version:counter',pk='ca_key_generation_id',common=False,checks=["publication_state IN ('inactive','active','closed')"])
table(5,'crl_documents','ca_key_generation_id:uuid@ca_key_generations number_hex:hex? der_sha256:hash der:blob this_update:int next_update:int? covered_generation:counter? origin:a32 source_import_id:uuid?@import_batches',unique=['der_sha256'],checks=["origin IN ('generated','imported')","origin <> 'generated' OR (number_hex IS NOT NULL AND next_update IS NOT NULL AND covered_generation IS NOT NULL)",'next_update IS NULL OR next_update > this_update'])
table(6,'ca_transitions','source_authority_id:uuid@authorities target_authority_id:uuid?@authorities mode:a32 state:a32 reported_by:uuid@accounts reported_at:int reason:text',mutable=True,checks=["mode IN ('normal','emergency')","state IN ('in_progress','externally_completed','closed')",'target_authority_id IS NULL OR target_authority_id <> source_authority_id'])
table(6,'transition_impacts','transition_id:uuid@ca_transitions certificate_id:uuid@certificates replacement_certificate_id:uuid?@certificates reissued_at:int?',common=False,pk='transition_id,certificate_id')
table(6,'deployment_confirmations','transition_id:uuid@ca_transitions certificate_id:uuid?@certificates target_label:text action:a32 confirmed_by:uuid?@accounts confirmed_at:int?',checks=["action IN ('trust_added','certificate_installed','trust_removed')"])
table(6,'tls_versions','source:a32 key_material_id:uuid@key_materials managed_certificate_id:uuid?@leaf_certificates.certificate_id leaf_der:blob chain_bundle:blob validated_service_url:text? not_after:int',checks=["source IN ('bootstrap','managed','external')","source = 'bootstrap' OR validated_service_url IS NOT NULL"])
table(6,'tls_changes','previous_version_id:uuid?@tls_versions candidate_version_id:uuid@tls_versions phase:a32 error_code:a64?',mutable=True,checks=["phase IN ('prepared','committed','applied','rolled_back','recovery_required')"])
table(6,'maintenance_runs','kind:a32 phase:a32 details_json:text started_at:int completed_at:int? error_code:a64?',mutable=True)
table(6,'maintenance_crl_requirements','maintenance_run_id:uuid@maintenance_runs ca_key_generation_id:uuid@ca_key_generations minimum_generation:counter minimum_number_hex:hex satisfied_crl_id:uuid?@crl_documents',pk='maintenance_run_id,ca_key_generation_id',common=False)
table(6,'jobs','kind:a32 dedup_key:a128 payload_version:counter payload_json:text state:a32 available_at:int lease_until:int? attempt_count:counter last_error_code:a64?',unique=['dedup_key'],mutable=True,checks=["state IN ('pending','running','succeeded','failed')"])
table(7,'installation','id:int setup_stage:a32 first_admin_id:uuid?@accounts active_encryption_generation_id:uuid@encryption_generations active_tls_version_id:uuid?@tls_versions service_mode:a32 updated_at:int version:counter',common=False,checks=['id = 1',"setup_stage IN ('account_required','pki_required','complete')","service_mode IN ('starting','serving','maintenance','recovery_required')","(setup_stage = 'account_required' AND first_admin_id IS NULL) OR (setup_stage <> 'account_required' AND first_admin_id IS NOT NULL)"])
table(7,'audit_events','occurred_at:int actor_kind:a32 actor_id:uuid? token_id:uuid? action:a64 target_type:a64 target_id:uuid? client_ip:a64? result:a32 details_json:text',checks=["actor_kind IN ('account','download_token','cli','system','anonymous')","result IN ('success','failure')"])
table(7,'audit_event_scopes','event_id:uuid@audit_events authority_id:uuid@authorities',common=False,pk='event_id,authority_id')

INDEXES = {
'certificates':['not_after,id','issuer_ca_key_generation_id,not_after','key_material_id,id'],
'leaf_certificates':['series_id,certificate_id'],
'certificate_sans':['type,normalized_value_hash'],
'key_deliveries':['state,expires_at'],
'download_tokens':['key_delivery_id,invalidated_at','certificate_id,purpose,invalidated_at','expires_at'],
'sessions':['account_id,absolute_expires_at'], 'password_reset_tokens':['account_id,expires_at'],
'jobs':['state,available_at'], 'audit_events':['occurred_at,id','actor_id,occurred_at','client_ip,occurred_at'],
'audit_event_scopes':['authority_id,event_id'], 'crl_documents':['ca_key_generation_id,created_at'],
'revocations':['certificate_id'], 'ca_takeovers':['ca_key_generation_id,state'],
}
GROUPS=['metadata','identity','keys','pki','delivery','revocation','operations','installation_audit']

def sqltype(t,d):
    if t in ('int','counter'): return 'INTEGER' if d=='sqlite' else 'BIGINT'
    if t=='bool': return 'BOOLEAN' if d=='postgres' else ('INTEGER' if d=='sqlite' else 'BOOLEAN')
    if t=='blob': return {'sqlite':'BLOB','postgres':'BYTEA','mysql':'LONGBLOB','mariadb':'LONGBLOB'}[d]
    if t=='text': return 'LONGTEXT' if d in ('mysql','mariadb') else 'TEXT'
    n={'uuid':36,'hash':64,'hex':40}.get(t,int(t[1:]) if t.startswith('a') else 0)
    return 'TEXT' if d=='sqlite' else f'VARCHAR({n})'+(' CHARACTER SET ascii COLLATE ascii_bin' if d in ('mysql','mariadb') else ' COLLATE "C"')

def fk_sql(name,n,fk):
    target,_,col=fk.partition('.');col=col or 'id'
    # Short stable names meet PostgreSQL's 63-byte identifier limit.
    cname='fk_'+hashlib.sha256((name+'.'+n).encode()).hexdigest()[:16]
    return f'CONSTRAINT {cname} FOREIGN KEY ({n}) REFERENCES {target} ({col}) ON DELETE RESTRICT'

def generate():
    byname={t['name']:t for t in TABLES}
    for t in TABLES:
        for n,typ,nullable,fk in t['columns']:
            if fk:
                target,_,col=fk.partition('.');col=col or 'id'
                assert target in byname and col in [x[0] for x in byname[target]['columns']],(t['name'],fk)
    files={}
    for d in ['sqlite','postgres','mysql','mariadb']:
        groups=[[] for _ in GROUPS]; deferred=[]
        for t in TABLES:
            name=t['name']; lines=[]; local_fks=[]; checks=list(t['checks'])
            for n,typ,nullable,fk in t['columns']:
                lines.append(f'    {n} {sqltype(typ,d)}'+('' if nullable else ' NOT NULL'))
                if typ in ('uuid','hash'): checks.append(f'length({n}) = '+str(36 if typ=='uuid' else 64))
                if typ=='hex':checks += [f'length({n}) BETWEEN 1 AND 40',f"(length({n}) = 1 OR substr({n},1,1) <> '0')"]
                if typ.startswith('a'): checks.append(f'length({n}) <= {int(typ[1:])}')
                if typ=='hex': checks.append(f"{n} NOT GLOB '*[^0-9a-f]*'" if d=='sqlite' else (f"{n} ~ '^[0-9a-f]+$'" if d=='postgres' else f"{n} REGEXP '^[0-9a-f]+$'"))
                if typ=='counter':checks.append(f'{n} >= 0')
                if typ=='bool' and d!='postgres': checks.append(f'{n} IN (0,1)')
                if fk:
                    clause=fk_sql(name,n,fk)
                    if d=='sqlite':local_fks.append('    '+clause)
                    else: deferred.append(f'ALTER TABLE {name} ADD {clause};')
            lines += local_fks
            lines.append('    PRIMARY KEY ('+', '.join(t['pk'])+')')
            for u in t['unique']:lines.append('    UNIQUE ('+', '.join(u)+')')
            for chk in checks:
                if d=='postgres': chk=chk.replace('length(nonce)','octet_length(nonce)')
                lines.append('    CHECK ('+chk+')')
            end=' ENGINE=InnoDB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;' if d in ('mysql','mariadb') else ';'
            groups[t['group']].append('CREATE TABLE '+name+' (\n'+',\n'.join(lines)+'\n)'+end)
        groups[7] += deferred
        for name,idxs in INDEXES.items():
            for i,cols in enumerate(idxs): groups[7].append(f'CREATE INDEX ix_{name}_{i+1} ON {name} ({cols});')
        folder=ROOT/'internal/storage/migrations'/d;folder.mkdir(parents=True,exist_ok=True)
        for i,statements in enumerate(groups):
            file=folder/f'{i:03}_{GROUPS[i]}.sql'
            data='-- Initial unreleased schema, generated by tools/generate_migrations.py.\n-- Execute statements under the migration runner exclusive lock.\n\n'+'\n\n'.join(statements)+'\n'
            file.write_text(data);files[str(file.relative_to(ROOT))]=hashlib.sha256(data.encode()).hexdigest()
    (ROOT/'internal/storage/migrations/manifest.json').write_text(json.dumps({'schema_version':7,'files':files},indent=2)+'\n')

if __name__=='__main__':generate()
