-- Explicit sync namespace transition; no data retirement or activation.
-- Uses only original baseline migrator/runtime privileges in existing public.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM nddev_schema_meta WHERE key='schema_version' AND value='10') THEN
        RAISE EXCEPTION 'replica namespace requires schema10';
    END IF;
END $$;
LOCK TABLE public.nds_sync_counters, public.nds_sync_entities,
    public.nds_sync_operations, public.nds_sync_nonces IN ACCESS EXCLUSIVE MODE;
ALTER TABLE public.nds_sync_counters RENAME TO nds_replica_counters;
ALTER TABLE public.nds_sync_entities RENAME TO nds_replica_entities;
ALTER TABLE public.nds_sync_operations RENAME TO nds_replica_operations;
ALTER TABLE public.nds_sync_nonces RENAME TO nds_replica_nonces;

ALTER TABLE public.nds_replica_counters
 ADD COLUMN admission_version SMALLINT NOT NULL DEFAULT 2 CHECK(admission_version IN(2,3)),
 ADD COLUMN floor_seq BIGINT NOT NULL DEFAULT 0 CHECK(floor_seq BETWEEN 0 AND 9007199254740991),
 ADD COLUMN base_seq BIGINT NOT NULL DEFAULT 0 CHECK(base_seq=floor_seq AND floor_seq<=server_seq),
 ADD CONSTRAINT sync_admission_floor CHECK(admission_version=3 OR(floor_seq=0 AND base_seq=0));
ALTER TABLE public.nds_replica_operations
 ADD COLUMN entity_type TEXT,
 ADD COLUMN entity_id TEXT,
 ADD COLUMN base_revision BIGINT,
 ADD COLUMN wire_version SMALLINT NOT NULL DEFAULT 2,
 ADD COLUMN basis_seq BIGINT,
 ADD COLUMN resolved_through_seq BIGINT NOT NULL DEFAULT 0,
 ADD COLUMN applied_revision BIGINT,
 ADD COLUMN current_revision BIGINT,
 ADD COLUMN request_bytes INTEGER,
 ADD COLUMN result_bytes INTEGER;
-- Projection only. Exact bytea request/result/fingerprint/status are untouched.
-- Existing source admits only V2 before this migration; malformed originals
-- abort instead of being normalized, dropped or silently reinterpreted.
UPDATE public.nds_replica_operations SET
 entity_type=convert_from(request_body,'UTF8')::jsonb->>'entity_type',
 entity_id=convert_from(request_body,'UTF8')::jsonb->>'entity_id',
 base_revision=(convert_from(request_body,'UTF8')::jsonb->>'base_revision')::bigint,
 wire_version=(convert_from(request_body,'UTF8')::jsonb->>'schema_version')::smallint,
 applied_revision=CASE WHEN status=201 THEN(convert_from(result_body,'UTF8')::jsonb->>'revision')::bigint END,
 current_revision=CASE WHEN status=409 THEN(convert_from(result_body,'UTF8')::jsonb->>'current_revision')::bigint END,
 request_bytes=octet_length(request_body),result_bytes=octet_length(result_body);
ALTER TABLE public.nds_replica_operations
 ALTER COLUMN entity_type SET NOT NULL,ALTER COLUMN entity_id SET NOT NULL,
 ALTER COLUMN base_revision SET NOT NULL,ALTER COLUMN request_bytes SET NOT NULL,ALTER COLUMN result_bytes SET NOT NULL,
 ADD CONSTRAINT sync_metadata_bounds CHECK(
  base_revision BETWEEN 0 AND 9007199254740991 AND wire_version IN(2,3)
  AND request_bytes=octet_length(request_body) AND result_bytes=octet_length(result_body)
  AND resolved_through_seq BETWEEN 0 AND 9007199254740991
  AND (basis_seq IS NULL OR basis_seq BETWEEN 0 AND 9007199254740991)
  AND ((status=201 AND applied_revision IS NOT NULL AND applied_revision BETWEEN 1 AND 9007199254740991 AND current_revision IS NULL)
    OR(status=409 AND applied_revision IS NULL AND current_revision IS NOT NULL AND current_revision BETWEEN 0 AND 9007199254740991)));
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.nds_replica_operations WHERE wire_version<>2) THEN
  RAISE EXCEPTION 'unexpected pre-lifecycle operation version';
 END IF;
END $$;
ALTER TABLE public.nds_replica_entities ADD COLUMN applied_seq BIGINT;
UPDATE public.nds_replica_entities e SET applied_seq=(SELECT max(o.server_seq) FROM public.nds_replica_operations o
 WHERE o.user_id=e.user_id AND o.tenant_id=e.tenant_id AND o.entity_type=e.entity_type AND o.entity_id=e.entity_id AND o.status=201);
ALTER TABLE public.nds_replica_entities ALTER COLUMN applied_seq SET NOT NULL;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.nds_replica_entities e JOIN public.nds_replica_operations o
  ON o.user_id=e.user_id AND o.tenant_id=e.tenant_id AND o.server_seq=e.applied_seq
  WHERE o.status<>201 OR o.applied_revision<>e.revision OR o.request_body<>e.request_body) THEN
  RAISE EXCEPTION 'current original binding mismatch';
 END IF;
 IF EXISTS(SELECT 1 FROM public.nds_replica_counters c FULL JOIN
  (SELECT user_id,tenant_id,count(*) AS n,max(server_seq) AS head,sum(2*request_bytes+result_bytes) AS bytes FROM public.nds_replica_operations GROUP BY user_id,tenant_id) o
  ON o.user_id=c.user_id AND o.tenant_id=c.tenant_id
  WHERE c.user_id IS NULL OR c.server_seq<>c.operation_count
   OR c.server_seq<>COALESCE(o.head,0) OR c.operation_count<>COALESCE(o.n,0) OR c.stored_bytes<>COALESCE(o.bytes,0)) THEN
  RAISE EXCEPTION 'retained counter mismatch';
 END IF;
END $$;
ALTER TABLE public.nds_replica_entities ADD CONSTRAINT sync_current_original
 FOREIGN KEY(user_id,tenant_id,applied_seq) REFERENCES public.nds_replica_operations(user_id,tenant_id,server_seq) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.nds_replica_base_members(
 user_id TEXT NOT NULL,tenant_id TEXT NOT NULL,server_seq BIGINT NOT NULL,
 PRIMARY KEY(user_id,tenant_id,server_seq),
 FOREIGN KEY(user_id,tenant_id,server_seq) REFERENCES public.nds_replica_operations(user_id,tenant_id,server_seq));
GRANT SELECT ON public.nds_replica_base_members TO nds_runtime;

-- Namespace is the old-reader/writer barrier. No old-name aliases or stored
-- procedure policy surface. Runtime cannot activate a new owner admission phase.
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON public.nds_replica_counters FROM nds_runtime;
GRANT INSERT(user_id,tenant_id),UPDATE(clock_floor_ms,root_key_id,server_seq,operation_count,stored_bytes,floor_seq,base_seq) ON public.nds_replica_counters TO nds_runtime;
GRANT DELETE ON public.nds_replica_operations TO nds_runtime;
GRANT SELECT,INSERT,DELETE ON public.nds_replica_base_members TO nds_runtime;
UPDATE nddev_schema_meta SET value='11',updated_at=NOW() WHERE key='schema_version';
