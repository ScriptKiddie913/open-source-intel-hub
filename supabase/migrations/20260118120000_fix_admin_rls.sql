-- Allow admins to view all profiles
CREATE POLICY "Admins can view all profiles"
  ON public.profiles FOR SELECT
  USING (public.is_admin(auth.uid()));

-- Allow admins to view all search history
CREATE POLICY "Admins can view all search history"
  ON public.search_history FOR SELECT
  USING (public.is_admin(auth.uid()));

-- Allow admins to view all monitoring items
CREATE POLICY "Admins can view all monitoring items"
  ON public.monitoring_items FOR SELECT
  USING (public.is_admin(auth.uid()));

-- Allow admins to view all monitoring alerts
CREATE POLICY "Admins can view all monitoring alerts"
  ON public.monitoring_alerts FOR SELECT
  USING (public.is_admin(auth.uid()));

-- Allow admins to view all user sessions
CREATE POLICY "Admins can view all user sessions"
  ON public.user_sessions FOR SELECT
  USING (public.is_admin(auth.uid()));

-- Allow admins to view all saved graphs
CREATE POLICY "Admins can view all saved graphs"
  ON public.saved_graphs FOR SELECT
  USING (public.is_admin(auth.uid()));
