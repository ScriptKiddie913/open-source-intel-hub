import { serve } from "https://deno.land/std@0.190.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface PanicAlertRequest {
  to: string;
  ipAddress: string | null;
  location: {
    latitude: number;
    longitude: number;
    accuracy: number;
    address?: string;
  } | null;
  message: string;
  deviceInfo: {
    userAgent: string;
    platform: string;
    language: string;
    screenWidth: number;
    screenHeight: number;
    timestamp: string;
  };
  userEmail?: string;
}

serve(async (req: Request): Promise<Response> => {
  // Handle CORS
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const resendApiKey = Deno.env.get("RESEND_API_KEY");
    
    if (!resendApiKey) {
      console.error("[Panic Alert] RESEND_API_KEY not configured");
      return new Response(
        JSON.stringify({ error: "Email service not configured. Please configure RESEND_API_KEY." }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const data: PanicAlertRequest = await req.json();
    const { to, ipAddress, location, message, deviceInfo, userEmail } = data;

    const mapLink = location 
      ? `https://www.google.com/maps?q=${location.latitude},${location.longitude}`
      : null;

    const locationText = location
      ? `
        <p><strong>Coordinates:</strong> ${location.latitude}, ${location.longitude}</p>
        <p><strong>Accuracy:</strong> ${location.accuracy.toFixed(0)} meters</p>
        ${location.address ? `<p><strong>Address:</strong> ${location.address}</p>` : ''}
        ${mapLink ? `<p><a href="${mapLink}" style="color: #ef4444;">View on Google Maps</a></p>` : ''}
      `
      : '<p>Location could not be determined</p>';

    const emailHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>EMERGENCY ALERT</title>
      </head>
      <body style="font-family: Arial, sans-serif; background-color: #1a1a1a; color: #ffffff; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #2d2d2d; border-radius: 12px; overflow: hidden;">
          <div style="background: linear-gradient(135deg, #dc2626, #991b1b); padding: 24px; text-align: center;">
            <h1 style="margin: 0; color: white; font-size: 28px;">🚨 EMERGENCY PANIC ALERT 🚨</h1>
          </div>
          
          <div style="padding: 24px;">
            <div style="background-color: #ef4444; color: white; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px;">
              <strong>Alert Time:</strong> ${deviceInfo.timestamp}
            </div>
            
            ${userEmail ? `
              <div style="margin-bottom: 20px; padding: 16px; background-color: #374151; border-radius: 8px;">
                <h3 style="margin: 0 0 8px 0; color: #fbbf24;">User Information</h3>
                <p style="margin: 0;"><strong>Email:</strong> ${userEmail}</p>
              </div>
            ` : ''}
            
            <div style="margin-bottom: 20px; padding: 16px; background-color: #374151; border-radius: 8px;">
              <h3 style="margin: 0 0 8px 0; color: #fbbf24;">Emergency Message</h3>
              <p style="margin: 0; font-size: 16px;">${message}</p>
            </div>
            
            <div style="margin-bottom: 20px; padding: 16px; background-color: #374151; border-radius: 8px;">
              <h3 style="margin: 0 0 8px 0; color: #fbbf24;">IP Address</h3>
              <p style="margin: 0; font-family: monospace; font-size: 18px;">${ipAddress || 'Unknown'}</p>
            </div>
            
            <div style="margin-bottom: 20px; padding: 16px; background-color: #374151; border-radius: 8px;">
              <h3 style="margin: 0 0 8px 0; color: #fbbf24;">Location</h3>
              ${locationText}
            </div>
            
            <div style="margin-bottom: 20px; padding: 16px; background-color: #374151; border-radius: 8px;">
              <h3 style="margin: 0 0 8px 0; color: #fbbf24;">Device Information</h3>
              <p><strong>Platform:</strong> ${deviceInfo.platform}</p>
              <p><strong>Language:</strong> ${deviceInfo.language}</p>
              <p><strong>Screen:</strong> ${deviceInfo.screenWidth}x${deviceInfo.screenHeight}</p>
              <p style="font-size: 12px; color: #9ca3af; word-break: break-all;"><strong>User Agent:</strong> ${deviceInfo.userAgent}</p>
            </div>
          </div>
          
          <div style="background-color: #1f1f1f; padding: 16px; text-align: center;">
            <p style="margin: 0; font-size: 12px; color: #6b7280;">
              This is an automated emergency alert from Phoenix OSINT Platform
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

    // Send email using Resend API directly
    const emailResponse = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${resendApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "Phoenix Alert <onboarding@resend.dev>",
        to: [to],
        subject: `🚨 EMERGENCY PANIC ALERT - ${new Date().toLocaleString()}`,
        html: emailHtml,
      }),
    });

    const emailResult = await emailResponse.json();

    if (!emailResponse.ok) {
      console.error("[Panic Alert] Email API error:", emailResult);
      throw new Error(emailResult.message || "Failed to send email");
    }

    console.log("[Panic Alert] Email sent:", emailResult);

    return new Response(
      JSON.stringify({ success: true, id: emailResult.id }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    console.error("[Panic Alert] Error:", errorMessage);
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
