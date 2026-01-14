-- Create panic_alerts table for storing emergency alerts
CREATE TABLE public.panic_alerts (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  ip_address TEXT,
  location JSONB,
  message TEXT,
  device_info JSONB,
  status TEXT NOT NULL DEFAULT 'sent',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.panic_alerts ENABLE ROW LEVEL SECURITY;

-- Users can insert their own panic alerts
CREATE POLICY "Users can insert own panic alerts" 
ON public.panic_alerts 
FOR INSERT 
WITH CHECK (auth.uid() = user_id);

-- Users can view their own panic alerts
CREATE POLICY "Users can view own panic alerts" 
ON public.panic_alerts 
FOR SELECT 
USING (auth.uid() = user_id);

-- Create index for faster queries
CREATE INDEX idx_panic_alerts_user_id ON public.panic_alerts(user_id);
CREATE INDEX idx_panic_alerts_created_at ON public.panic_alerts(created_at DESC);