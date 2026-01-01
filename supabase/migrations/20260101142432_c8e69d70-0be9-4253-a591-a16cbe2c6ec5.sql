-- Create profiles table for user data
CREATE TABLE public.profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT,
  display_name TEXT,
  avatar_url TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Profiles policies
CREATE POLICY "Users can view own profile"
  ON public.profiles FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can update own profile"
  ON public.profiles FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own profile"
  ON public.profiles FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Create search history table
CREATE TABLE public.search_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  query TEXT NOT NULL,
  search_type TEXT NOT NULL, -- 'domain', 'ip', 'cve', 'darkweb', 'breach', 'username', etc.
  results_count INTEGER DEFAULT 0,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.search_history ENABLE ROW LEVEL SECURITY;

-- Search history policies
CREATE POLICY "Users can view own search history"
  ON public.search_history FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own search history"
  ON public.search_history FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete own search history"
  ON public.search_history FOR DELETE
  USING (auth.uid() = user_id);

-- Create saved graphs table
CREATE TABLE public.saved_graphs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  graph_data JSONB NOT NULL DEFAULT '{}',
  nodes_count INTEGER DEFAULT 0,
  edges_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.saved_graphs ENABLE ROW LEVEL SECURITY;

-- Saved graphs policies
CREATE POLICY "Users can view own graphs"
  ON public.saved_graphs FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own graphs"
  ON public.saved_graphs FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own graphs"
  ON public.saved_graphs FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own graphs"
  ON public.saved_graphs FOR DELETE
  USING (auth.uid() = user_id);

-- Create monitoring items table
CREATE TABLE public.monitoring_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  monitor_type TEXT NOT NULL, -- 'domain', 'ip', 'email', 'keyword', 'hash', 'cve', 'username'
  value TEXT NOT NULL, -- The actual value being monitored
  status TEXT NOT NULL DEFAULT 'active', -- 'active', 'paused', 'alert'
  alert_threshold TEXT DEFAULT 'any', -- 'any', 'high', 'critical'
  last_checked_at TIMESTAMP WITH TIME ZONE,
  last_alert_at TIMESTAMP WITH TIME ZONE,
  alerts_count INTEGER DEFAULT 0,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.monitoring_items ENABLE ROW LEVEL SECURITY;

-- Monitoring items policies
CREATE POLICY "Users can view own monitoring items"
  ON public.monitoring_items FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own monitoring items"
  ON public.monitoring_items FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own monitoring items"
  ON public.monitoring_items FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own monitoring items"
  ON public.monitoring_items FOR DELETE
  USING (auth.uid() = user_id);

-- Create monitoring alerts table
CREATE TABLE public.monitoring_alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  monitoring_item_id UUID NOT NULL REFERENCES public.monitoring_items(id) ON DELETE CASCADE,
  severity TEXT NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
  title TEXT NOT NULL,
  description TEXT,
  source TEXT,
  is_read BOOLEAN DEFAULT false,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.monitoring_alerts ENABLE ROW LEVEL SECURITY;

-- Monitoring alerts policies
CREATE POLICY "Users can view own alerts"
  ON public.monitoring_alerts FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can update own alerts"
  ON public.monitoring_alerts FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own alerts"
  ON public.monitoring_alerts FOR DELETE
  USING (auth.uid() = user_id);

-- Create user sessions table for tracking work sessions
CREATE TABLE public.user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  session_name TEXT,
  session_data JSONB NOT NULL DEFAULT '{}',
  last_active_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;

-- User sessions policies
CREATE POLICY "Users can view own sessions"
  ON public.user_sessions FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own sessions"
  ON public.user_sessions FOR INSERT
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own sessions"
  ON public.user_sessions FOR UPDATE
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own sessions"
  ON public.user_sessions FOR DELETE
  USING (auth.uid() = user_id);

-- Create function to update timestamps
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_saved_graphs_updated_at
  BEFORE UPDATE ON public.saved_graphs
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_monitoring_items_updated_at
  BEFORE UPDATE ON public.monitoring_items
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Auto-create profile on user signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (user_id, email)
  VALUES (NEW.id, NEW.email);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Create indexes for better query performance
CREATE INDEX idx_search_history_user_id ON public.search_history(user_id);
CREATE INDEX idx_search_history_created_at ON public.search_history(created_at DESC);
CREATE INDEX idx_saved_graphs_user_id ON public.saved_graphs(user_id);
CREATE INDEX idx_monitoring_items_user_id ON public.monitoring_items(user_id);
CREATE INDEX idx_monitoring_items_status ON public.monitoring_items(status);
CREATE INDEX idx_monitoring_alerts_user_id ON public.monitoring_alerts(user_id);
CREATE INDEX idx_monitoring_alerts_is_read ON public.monitoring_alerts(is_read);
CREATE INDEX idx_user_sessions_user_id ON public.user_sessions(user_id);