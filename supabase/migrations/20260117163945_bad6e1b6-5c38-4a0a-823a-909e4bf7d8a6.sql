-- Create role enum
CREATE TYPE public.app_role AS ENUM ('admin', 'moderator', 'user');

-- Create user_roles table for secure role management
CREATE TABLE public.user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    role app_role NOT NULL DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE (user_id, role)
);

-- Create admin_messages table for admin-to-user messages in monitoring section
CREATE TABLE public.admin_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    to_user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    severity TEXT DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on both tables
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_messages ENABLE ROW LEVEL SECURITY;

-- Create security definer function to check user role (prevents RLS recursion)
CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role app_role)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id
      AND role = _role
  )
$$;

-- Create function to check if user is admin
CREATE OR REPLACE FUNCTION public.is_admin(_user_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.user_roles
    WHERE user_id = _user_id
      AND role = 'admin'
  )
$$;

-- RLS Policies for user_roles
-- Only admins can view all roles
CREATE POLICY "Admins can view all roles"
ON public.user_roles
FOR SELECT
TO authenticated
USING (public.is_admin(auth.uid()) OR user_id = auth.uid());

-- Only admins can insert roles
CREATE POLICY "Admins can create roles"
ON public.user_roles
FOR INSERT
TO authenticated
WITH CHECK (public.is_admin(auth.uid()));

-- Only admins can update roles
CREATE POLICY "Admins can update roles"
ON public.user_roles
FOR UPDATE
TO authenticated
USING (public.is_admin(auth.uid()));

-- Only admins can delete roles
CREATE POLICY "Admins can delete roles"
ON public.user_roles
FOR DELETE
TO authenticated
USING (public.is_admin(auth.uid()));

-- RLS Policies for admin_messages
-- Users can view messages sent to them
CREATE POLICY "Users can view their own messages"
ON public.admin_messages
FOR SELECT
TO authenticated
USING (to_user_id = auth.uid() OR from_user_id = auth.uid() OR public.is_admin(auth.uid()));

-- Only admins can create messages
CREATE POLICY "Admins can create messages"
ON public.admin_messages
FOR INSERT
TO authenticated
WITH CHECK (public.is_admin(auth.uid()));

-- Users can mark their messages as read
CREATE POLICY "Users can update their messages"
ON public.admin_messages
FOR UPDATE
TO authenticated
USING (to_user_id = auth.uid() OR public.is_admin(auth.uid()));

-- Only admins can delete messages
CREATE POLICY "Admins can delete messages"
ON public.admin_messages
FOR DELETE
TO authenticated
USING (public.is_admin(auth.uid()));

-- Add trigger for updated_at on admin_messages
CREATE TRIGGER update_admin_messages_updated_at
BEFORE UPDATE ON public.admin_messages
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Insert admin role for sagnik.saha.raptor@gmail.com
INSERT INTO public.user_roles (user_id, role)
VALUES ('bbc1a140-2b31-4491-af08-9832a28241ba', 'admin');

-- Create indexes for performance
CREATE INDEX idx_user_roles_user_id ON public.user_roles(user_id);
CREATE INDEX idx_user_roles_role ON public.user_roles(role);
CREATE INDEX idx_admin_messages_to_user ON public.admin_messages(to_user_id);
CREATE INDEX idx_admin_messages_from_user ON public.admin_messages(from_user_id);
CREATE INDEX idx_admin_messages_is_read ON public.admin_messages(is_read);