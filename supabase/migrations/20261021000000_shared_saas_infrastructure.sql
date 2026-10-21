CREATE TABLE IF NOT EXISTS public.tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.tenant_memberships (
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS tenant_memberships_user_idx
    ON public.tenant_memberships (user_id, created_at);

CREATE TABLE IF NOT EXISTS public.api_request_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS api_request_events_tenant_time_idx
    ON public.api_request_events (tenant_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS public.analysis_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    owner_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    filename text NOT NULL,
    storage_key text NOT NULL UNIQUE,
    size_bytes bigint NOT NULL CHECK (size_bytes > 0),
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('uploading', 'queued', 'running', 'done', 'error')),
    result jsonb,
    error text,
    capture_deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    lease_expires_at timestamptz
);

CREATE INDEX IF NOT EXISTS analysis_jobs_queue_idx
    ON public.analysis_jobs (created_at)
    WHERE status = 'queued';

CREATE INDEX IF NOT EXISTS analysis_jobs_tenant_idx
    ON public.analysis_jobs (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS analysis_jobs_lease_idx
    ON public.analysis_jobs (lease_expires_at)
    WHERE status IN ('uploading', 'running');

CREATE TABLE IF NOT EXISTS public.analysis_leases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS analysis_leases_tenant_idx
    ON public.analysis_leases (tenant_id, expires_at);

CREATE TABLE IF NOT EXISTS public.queue_capacity_lock (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    touched_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.queue_capacity_lock (singleton)
VALUES (true)
ON CONFLICT (singleton) DO NOTHING;

CREATE OR REPLACE FUNCTION public.create_personal_tenant_for_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    new_tenant_id uuid;
    display_name text;
BEGIN
    display_name := COALESCE(
        NULLIF(NEW.raw_user_meta_data ->> 'workspace_name', ''),
        NULLIF(split_part(COALESCE(NEW.email, 'Workspace'), '@', 1), ''),
        'Workspace'
    );
    INSERT INTO public.tenants (name)
    VALUES (display_name || ' workspace')
    RETURNING id INTO new_tenant_id;

    INSERT INTO public.tenant_memberships (tenant_id, user_id, role)
    VALUES (new_tenant_id, NEW.id, 'owner');
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS create_personal_tenant_after_signup ON auth.users;
CREATE TRIGGER create_personal_tenant_after_signup
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.create_personal_tenant_for_new_user();

REVOKE ALL ON FUNCTION public.create_personal_tenant_for_new_user()
    FROM PUBLIC, anon, authenticated;

DO $$
DECLARE
    existing_user record;
    new_tenant_id uuid;
BEGIN
    FOR existing_user IN
        SELECT users.id, users.email
        FROM auth.users AS users
        WHERE NOT EXISTS (
            SELECT 1
            FROM public.tenant_memberships AS membership
            WHERE membership.user_id = users.id
        )
    LOOP
        INSERT INTO public.tenants (name)
        VALUES (
            COALESCE(
                NULLIF(split_part(COALESCE(existing_user.email, 'Workspace'), '@', 1), ''),
                'Workspace'
            ) || ' workspace'
        )
        RETURNING id INTO new_tenant_id;

        INSERT INTO public.tenant_memberships (tenant_id, user_id, role)
        VALUES (new_tenant_id, existing_user.id, 'owner');
    END LOOP;
END;
$$;

ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_request_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.analysis_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.analysis_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.queue_capacity_lock ENABLE ROW LEVEL SECURITY;

INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('pcap-captures', 'pcap-captures', false, 209715200)
ON CONFLICT (id) DO UPDATE
SET public = false,
    file_size_limit = EXCLUDED.file_size_limit;
