-- Migration: Add unique constraint for threat intelligence upsert support
-- This enables efficient deduplication when syncing from multiple sources

-- Add unique constraint on source_id and source_name combination
-- This prevents duplicate entries from the same source
DO $$ 
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint 
    WHERE conname = 'threat_intelligence_source_unique'
  ) THEN
    ALTER TABLE public.threat_intelligence 
    ADD CONSTRAINT threat_intelligence_source_unique 
    UNIQUE (source_id, source_name);
  END IF;
END $$;

-- Add additional indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_last_seen 
ON public.threat_intelligence(last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_threat_intelligence_confidence 
ON public.threat_intelligence(confidence_level DESC);

CREATE INDEX IF NOT EXISTS idx_threat_intelligence_tags 
ON public.threat_intelligence USING GIN(tags);

-- Update auto-cleanup function to handle higher capacity
CREATE OR REPLACE FUNCTION public.auto_cleanup_threat_intelligence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  record_count INTEGER;
  max_records INTEGER := 50000; -- Increased to 50K for 29+ sources
  threshold_count INTEGER;
  delete_count INTEGER;
BEGIN
  -- Get current record count
  SELECT COUNT(*) INTO record_count FROM public.threat_intelligence;
  
  -- Calculate 75% threshold
  threshold_count := (max_records * 75) / 100;
  
  -- If we're over 75%, delete oldest records to get to 60%
  IF record_count > threshold_count THEN
    delete_count := record_count - (max_records * 60 / 100);
    
    DELETE FROM public.threat_intelligence
    WHERE id IN (
      SELECT id FROM public.threat_intelligence
      ORDER BY created_at ASC
      LIMIT delete_count
    );
    
    RAISE NOTICE 'Auto-cleanup: Deleted % oldest threat intelligence records', delete_count;
  END IF;
  
  RETURN NEW;
END;
$$;

-- Create a view for easy threat statistics
CREATE OR REPLACE VIEW public.threat_statistics AS
SELECT 
  source_name,
  threat_type,
  severity_level,
  COUNT(*) as count,
  MAX(last_seen) as last_activity,
  AVG(confidence_level) as avg_confidence
FROM public.threat_intelligence
WHERE status = 'active'
GROUP BY source_name, threat_type, severity_level;

-- Grant select on view to anon and authenticated
GRANT SELECT ON public.threat_statistics TO anon, authenticated;

-- Create function to get threat count by source
CREATE OR REPLACE FUNCTION public.get_threat_counts_by_source()
RETURNS TABLE(source TEXT, threat_count BIGINT, last_sync TIMESTAMPTZ)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT 
    source_name as source,
    COUNT(*) as threat_count,
    MAX(created_at) as last_sync
  FROM public.threat_intelligence
  GROUP BY source_name
  ORDER BY threat_count DESC;
$$;

-- Create function to get severity distribution
CREATE OR REPLACE FUNCTION public.get_severity_distribution()
RETURNS TABLE(severity TEXT, count BIGINT, percentage NUMERIC)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
AS $$
  WITH total AS (
    SELECT COUNT(*) as total_count FROM public.threat_intelligence
  )
  SELECT 
    severity_level as severity,
    COUNT(*) as count,
    ROUND((COUNT(*)::NUMERIC / NULLIF(total.total_count, 0)) * 100, 2) as percentage
  FROM public.threat_intelligence, total
  GROUP BY severity_level, total.total_count
  ORDER BY 
    CASE severity_level
      WHEN 'critical' THEN 1
      WHEN 'high' THEN 2
      WHEN 'medium' THEN 3
      WHEN 'low' THEN 4
      ELSE 5
    END;
$$;

-- Allow anon users to read (for public dashboards)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies 
    WHERE schemaname = 'public' 
    AND tablename = 'threat_intelligence' 
    AND policyname = 'Allow anon read access'
  ) THEN
    CREATE POLICY "Allow anon read access"
    ON public.threat_intelligence
    FOR SELECT
    TO anon
    USING (true);
  END IF;
END $$;

-- Add comment to table
COMMENT ON TABLE public.threat_intelligence IS 
'Unified threat intelligence database synced from 29+ sources including abuse.ch, CISA KEV, APTmap, MITRE, and more.';
