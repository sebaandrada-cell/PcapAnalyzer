-- Defense in depth for the exposed `public` schema.
--
-- The API talks to Postgres with SUPABASE_DB_URL / the service role, which
-- bypass RLS, so the browser never needs direct table access. This migration
-- makes that explicit: anon gets nothing, signed-in users can only READ their
-- own rows, and nobody but the backend can write.

-- 1. Remove the default Supabase grants that expose every table to the Data API.
REVOKE ALL ON public.tenants, public.tenant_memberships, public.api_request_events,
    public.analysis_jobs, public.analysis_leases, public.queue_capacity_lock
    FROM anon, authenticated;

-- 2. Read-only access for signed-in users, scoped to their own rows.
GRANT SELECT ON public.tenants, public.tenant_memberships, public.analysis_jobs
    TO authenticated;

-- 3. Idempotent re-runs.
DROP POLICY IF EXISTS tenant_memberships_select_own ON public.tenant_memberships;
DROP POLICY IF EXISTS tenants_select_member ON public.tenants;
DROP POLICY IF EXISTS analysis_jobs_select_own ON public.analysis_jobs;

CREATE POLICY tenant_memberships_select_own ON public.tenant_memberships
    FOR SELECT TO authenticated
    USING (user_id = (SELECT auth.uid()));

CREATE POLICY tenants_select_member ON public.tenants
    FOR SELECT TO authenticated
    USING (id IN (
        SELECT tenant_id FROM public.tenant_memberships
        WHERE user_id = (SELECT auth.uid())
    ));

CREATE POLICY analysis_jobs_select_own ON public.analysis_jobs
    FOR SELECT TO authenticated
    USING (owner_id = (SELECT auth.uid()));

-- api_request_events, analysis_leases and queue_capacity_lock intentionally
-- have RLS enabled with NO policies: deny-all for anon and authenticated.
-- No INSERT/UPDATE/DELETE policy exists anywhere, so clients cannot write.

-- 4. Private bucket: no storage.objects policies for anon/authenticated means
--    captures are reachable only through the backend (service role). Keep the
--    per-file cap aligned with MAX_UPLOAD_MB to bound storage and egress.
UPDATE storage.buckets
SET public = false,
    file_size_limit = 52428800  -- 50 MiB; API accepts MAX_UPLOAD_MB (25 on Render)
WHERE id = 'pcap-captures';
