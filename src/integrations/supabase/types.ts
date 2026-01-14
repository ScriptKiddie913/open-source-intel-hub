export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.1"
  }
  public: {
    Tables: {
      monitoring_alerts: {
        Row: {
          created_at: string
          description: string | null
          id: string
          is_read: boolean | null
          metadata: Json | null
          monitoring_item_id: string
          severity: string
          source: string | null
          title: string
          user_id: string
        }
        Insert: {
          created_at?: string
          description?: string | null
          id?: string
          is_read?: boolean | null
          metadata?: Json | null
          monitoring_item_id: string
          severity?: string
          source?: string | null
          title: string
          user_id: string
        }
        Update: {
          created_at?: string
          description?: string | null
          id?: string
          is_read?: boolean | null
          metadata?: Json | null
          monitoring_item_id?: string
          severity?: string
          source?: string | null
          title?: string
          user_id?: string
        }
        Relationships: [
          {
            foreignKeyName: "monitoring_alerts_monitoring_item_id_fkey"
            columns: ["monitoring_item_id"]
            isOneToOne: false
            referencedRelation: "monitoring_items"
            referencedColumns: ["id"]
          },
        ]
      }
      monitoring_items: {
        Row: {
          alert_threshold: string | null
          alerts_count: number | null
          created_at: string
          id: string
          last_alert_at: string | null
          last_checked_at: string | null
          metadata: Json | null
          monitor_type: string
          name: string
          status: string
          updated_at: string
          user_id: string
          value: string
        }
        Insert: {
          alert_threshold?: string | null
          alerts_count?: number | null
          created_at?: string
          id?: string
          last_alert_at?: string | null
          last_checked_at?: string | null
          metadata?: Json | null
          monitor_type: string
          name: string
          status?: string
          updated_at?: string
          user_id: string
          value: string
        }
        Update: {
          alert_threshold?: string | null
          alerts_count?: number | null
          created_at?: string
          id?: string
          last_alert_at?: string | null
          last_checked_at?: string | null
          metadata?: Json | null
          monitor_type?: string
          name?: string
          status?: string
          updated_at?: string
          user_id?: string
          value?: string
        }
        Relationships: []
      }
      panic_alerts: {
        Row: {
          created_at: string
          device_info: Json | null
          id: string
          ip_address: string | null
          location: Json | null
          message: string | null
          status: string
          user_id: string
        }
        Insert: {
          created_at?: string
          device_info?: Json | null
          id?: string
          ip_address?: string | null
          location?: Json | null
          message?: string | null
          status?: string
          user_id: string
        }
        Update: {
          created_at?: string
          device_info?: Json | null
          id?: string
          ip_address?: string | null
          location?: Json | null
          message?: string | null
          status?: string
          user_id?: string
        }
        Relationships: []
      }
      profiles: {
        Row: {
          avatar_url: string | null
          created_at: string
          display_name: string | null
          email: string | null
          id: string
          updated_at: string
          user_id: string
        }
        Insert: {
          avatar_url?: string | null
          created_at?: string
          display_name?: string | null
          email?: string | null
          id?: string
          updated_at?: string
          user_id: string
        }
        Update: {
          avatar_url?: string | null
          created_at?: string
          display_name?: string | null
          email?: string | null
          id?: string
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      saved_graphs: {
        Row: {
          created_at: string
          description: string | null
          edges_count: number | null
          graph_data: Json
          id: string
          name: string
          nodes_count: number | null
          updated_at: string
          user_id: string
        }
        Insert: {
          created_at?: string
          description?: string | null
          edges_count?: number | null
          graph_data?: Json
          id?: string
          name: string
          nodes_count?: number | null
          updated_at?: string
          user_id: string
        }
        Update: {
          created_at?: string
          description?: string | null
          edges_count?: number | null
          graph_data?: Json
          id?: string
          name?: string
          nodes_count?: number | null
          updated_at?: string
          user_id?: string
        }
        Relationships: []
      }
      search_history: {
        Row: {
          created_at: string
          id: string
          metadata: Json | null
          query: string
          results_count: number | null
          search_type: string
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          metadata?: Json | null
          query: string
          results_count?: number | null
          search_type: string
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          metadata?: Json | null
          query?: string
          results_count?: number | null
          search_type?: string
          user_id?: string
        }
        Relationships: []
      }
      threat_intelligence: {
        Row: {
          attribution: Json | null
          confidence_level: number
          created_at: string
          description: string | null
          first_seen: string
          id: string
          indicators: Json | null
          last_seen: string
          metadata: Json | null
          raw_data: Json | null
          severity_level: string
          source_id: string
          source_name: string
          status: string
          tags: string[] | null
          targets: Json | null
          threat_type: string
          timeline: Json | null
          title: string
          ttps: Json | null
          updated_at: string
          user_id: string | null
        }
        Insert: {
          attribution?: Json | null
          confidence_level?: number
          created_at?: string
          description?: string | null
          first_seen?: string
          id?: string
          indicators?: Json | null
          last_seen?: string
          metadata?: Json | null
          raw_data?: Json | null
          severity_level?: string
          source_id: string
          source_name: string
          status?: string
          tags?: string[] | null
          targets?: Json | null
          threat_type?: string
          timeline?: Json | null
          title?: string
          ttps?: Json | null
          updated_at?: string
          user_id?: string | null
        }
        Update: {
          attribution?: Json | null
          confidence_level?: number
          created_at?: string
          description?: string | null
          first_seen?: string
          id?: string
          indicators?: Json | null
          last_seen?: string
          metadata?: Json | null
          raw_data?: Json | null
          severity_level?: string
          source_id?: string
          source_name?: string
          status?: string
          tags?: string[] | null
          targets?: Json | null
          threat_type?: string
          timeline?: Json | null
          title?: string
          ttps?: Json | null
          updated_at?: string
          user_id?: string | null
        }
        Relationships: []
      }
      user_sessions: {
        Row: {
          created_at: string
          id: string
          last_active_at: string
          session_data: Json
          session_name: string | null
          user_id: string
        }
        Insert: {
          created_at?: string
          id?: string
          last_active_at?: string
          session_data?: Json
          session_name?: string | null
          user_id: string
        }
        Update: {
          created_at?: string
          id?: string
          last_active_at?: string
          session_data?: Json
          session_name?: string | null
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {},
  },
} as const
