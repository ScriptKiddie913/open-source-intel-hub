import { serve } from "https://deno.land/std@0.190.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface ReportRequest {
  to: string;
  subject: string;
  report: string;
  userEmail?: string;
  reportType?: string;
}

serve(async (req: Request): Promise<Response> => {
  // Handle CORS
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const resendApiKey = Deno.env.get("RESEND_API_KEY");
    
    if (!resendApiKey) {
      console.error("[Report] RESEND_API_KEY not configured");
      return new Response(
        JSON.stringify({ error: "Email service not configured. Please configure RESEND_API_KEY." }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const data: ReportRequest = await req.json();
    const { to, subject, report, userEmail, reportType } = data;

    if (!report || report.trim().length === 0) {
      return new Response(
        JSON.stringify({ error: "Report content is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const timestamp = new Date().toLocaleString('en-US', {
      dateStyle: 'full',
      timeStyle: 'long',
    });

    const emailHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Intelligence Report</title>
      </head>
      <body style="font-family: Arial, sans-serif; background-color: #1a1a1a; color: #ffffff; padding: 20px;">
        <div style="max-width: 700px; margin: 0 auto; background-color: #2d2d2d; border-radius: 12px; overflow: hidden;">
          <div style="background: linear-gradient(135deg, #3b82f6, #1d4ed8); padding: 24px; text-align: center;">
            <h1 style="margin: 0; color: white; font-size: 28px;">📊 Intelligence Report</h1>
          </div>
          
          <div style="padding: 24px;">
            <div style="background-color: #3b82f6; color: white; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px;">
              <strong>Generated:</strong> ${timestamp}
            </div>
            
            ${userEmail ? `
              <div style="margin-bottom: 20px; padding: 16px; background-color: #374151; border-radius: 8px;">
                <h3 style="margin: 0 0 8px 0; color: #60a5fa;">Report Submitted By</h3>
                <p style="margin: 0;"><strong>Email:</strong> ${userEmail}</p>
              </div>
            ` : ''}
            
            ${reportType ? `
              <div style="margin-bottom: 20px; padding: 16px; background-color: #374151; border-radius: 8px;">
                <h3 style="margin: 0 0 8px 0; color: #60a5fa;">Report Type</h3>
                <p style="margin: 0; font-weight: bold; text-transform: uppercase; color: #fbbf24;">${reportType}</p>
              </div>
            ` : ''}
            
            <div style="margin-bottom: 20px; padding: 16px; background-color: #374151; border-radius: 8px;">
              <h3 style="margin: 0 0 12px 0; color: #60a5fa;">Report Subject</h3>
              <p style="margin: 0; font-size: 18px; font-weight: 600; color: #ffffff;">${subject}</p>
            </div>
            
            <div style="margin-bottom: 20px; padding: 20px; background-color: #1f2937; border-left: 4px solid #3b82f6; border-radius: 8px;">
              <h3 style="margin: 0 0 12px 0; color: #60a5fa;">Report Content</h3>
              <div style="margin: 0; font-size: 15px; line-height: 1.6; white-space: pre-wrap; word-wrap: break-word;">${report}</div>
            </div>
          </div>
          
          <div style="background-color: #1f1f1f; padding: 16px; text-align: center;">
            <p style="margin: 0; font-size: 12px; color: #6b7280;">
              This report was generated from Phoenix OSINT Intelligence Platform
            </p>
            <p style="margin: 8px 0 0 0; font-size: 11px; color: #4b5563;">
              Automated Report System • Phoenix OSINT Hub
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Send email using Resend API
    const emailResponse = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${resendApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "Phoenix Reports <onboarding@resend.dev>",
        to: [to],
        subject: `📊 ${subject}`,
        html: emailHtml,
      }),
    });

    const emailResult = await emailResponse.json();

    if (!emailResponse.ok) {
      console.error("[Report] Email API error:", emailResult);
      throw new Error(emailResult.message || "Failed to send report");
    }

    console.log("[Report] Email sent successfully:", emailResult);

    return new Response(
      JSON.stringify({ success: true, id: emailResult.id }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : "An unknown error occurred";
    console.error("[Report] Error:", errorMessage);
    
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
