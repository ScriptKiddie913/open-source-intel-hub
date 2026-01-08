import { useState } from 'react';
import type { FormEvent } from 'react';
import { FileText, Send, Loader2, CheckCircle2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface ReportButtonProps {
  className?: string;
}

export function ReportButton({ className }: ReportButtonProps) {
  const [open, setOpen] = useState(false);
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [subject, setSubject] = useState('');
  const [report, setReport] = useState('');
  const [reportType, setReportType] = useState('general');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (!subject.trim() || !report.trim()) {
      toast.error('Please fill in both subject and report content');
      return;
    }

    setSending(true);

    try {
      // Get current user (optional)
      const { data: { user } } = await supabase.auth.getUser();

      // Send report via edge function
      const { data, error } = await supabase.functions.invoke('send-report', {
        body: {
          to: 'souvikpanja582@gmail.com',
          subject: subject.trim(),
          report: report.trim(),
          reportType,
          userEmail: user?.email || 'Anonymous User',
        },
      });

      if (error) {
        console.error('[Report] Error:', error);
        throw error;
      }

      console.log('[Report] Success:', data);
      setSent(true);
      toast.success('Report sent successfully!');

      // Reset after 2 seconds
      setTimeout(() => {
        handleClose();
      }, 2000);

    } catch (err) {
      console.error('[Report] Failed to send:', err);
      toast.error('Failed to send report. Please try again.');
    } finally {
      setSending(false);
    }
  };

  const handleClose = () => {
    setOpen(false);
    setSubject('');
    setReport('');
    setReportType('general');
    setSent(false);
    setSending(false);
  };

  return (
    <>
      {/* Floating Report Button */}
      <button
        onClick={() => setOpen(true)}
        className={cn(
          "fixed z-50 group",
          "bottom-6 right-6",
          className
        )}
        title="Submit Intelligence Report"
      >
        <div className="relative">
          {/* Subtle glow */}
          <div className="absolute inset-0 rounded-full bg-blue-500 opacity-30 blur-md group-hover:opacity-50 transition-opacity" />
          
          {/* Main button */}
          <div className="relative flex items-center justify-center w-14 h-14 rounded-full bg-gradient-to-br from-blue-600 to-blue-800 border-2 border-blue-400/50 shadow-xl shadow-blue-500/20 hover:shadow-blue-500/40 transition-all duration-300 group-hover:scale-105">
            <FileText className="h-6 w-6 text-white" />
          </div>
          
          {/* Badge */}
          <span className="absolute -top-1 -right-1 px-1.5 py-0.5 text-[9px] font-bold bg-blue-500 text-white rounded-full shadow-md">
            Report
          </span>
        </div>
      </button>

      {/* Report Dialog */}
      <Dialog open={open} onOpenChange={(v) => !v && !sending && handleClose()}>
        <DialogContent className="sm:max-w-[550px] bg-gradient-to-b from-slate-900 to-slate-950 border-blue-500/30">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-blue-400">
              <FileText className="h-5 w-5" />
              Submit Intelligence Report
            </DialogTitle>
            <DialogDescription>
              Send a detailed intelligence report to the analysis team
            </DialogDescription>
          </DialogHeader>

          {sent ? (
            <div className="py-8 flex flex-col items-center justify-center text-center">
              <CheckCircle2 className="h-16 w-16 text-green-500 mb-4 animate-pulse" />
              <h3 className="text-xl font-semibold text-green-400 mb-2">Report Sent!</h3>
              <p className="text-slate-400">Your report has been successfully submitted.</p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Report Type */}
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-300">
                  Report Type
                </label>
                <Select value={reportType} onValueChange={setReportType}>
                  <SelectTrigger className="bg-slate-800 border-slate-700 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-800 border-slate-700">
                    <SelectItem value="general">General Report</SelectItem>
                    <SelectItem value="threat">Threat Intelligence</SelectItem>
                    <SelectItem value="vulnerability">Vulnerability Report</SelectItem>
                    <SelectItem value="breach">Data Breach</SelectItem>
                    <SelectItem value="malware">Malware Analysis</SelectItem>
                    <SelectItem value="apt">APT Activity</SelectItem>
                    <SelectItem value="incident">Security Incident</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Subject */}
              <div className="space-y-2">
                <label htmlFor="subject" className="text-sm font-medium text-slate-300">
                  Subject
                </label>
                <Input
                  id="subject"
                  placeholder="Brief summary of the report..."
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="bg-slate-800 border-slate-700 text-white placeholder:text-slate-500"
                  maxLength={200}
                  disabled={sending}
                />
                <p className="text-xs text-slate-500 text-right">
                  {subject.length}/200
                </p>
              </div>

              {/* Report Content */}
              <div className="space-y-2">
                <label htmlFor="report" className="text-sm font-medium text-slate-300">
                  Report Details
                </label>
                <Textarea
                  id="report"
                  placeholder="Enter detailed information about your findings, observations, or intelligence data..."
                  value={report}
                  onChange={(e) => setReport(e.target.value)}
                  className="bg-slate-800 border-slate-700 text-white placeholder:text-slate-500 min-h-[200px] resize-none"
                  maxLength={5000}
                  disabled={sending}
                />
                <p className="text-xs text-slate-500 text-right">
                  {report.length}/5000
                </p>
              </div>

              {/* Actions */}
              <div className="flex gap-3 pt-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleClose}
                  disabled={sending}
                  className="flex-1 bg-slate-800 border-slate-700 hover:bg-slate-700"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={sending || !subject.trim() || !report.trim()}
                  className="flex-1 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800"
                >
                  {sending ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Sending...
                    </>
                  ) : (
                    <>
                      <Send className="mr-2 h-4 w-4" />
                      Send Report
                    </>
                  )}
                </Button>
              </div>

              {/* Info */}
              <div className="flex items-start gap-2 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                <FileText className="h-4 w-4 text-blue-400 mt-0.5 flex-shrink-0" />
                <p className="text-xs text-slate-400 leading-relaxed">
                  Your report will be sent to the intelligence analysis team at{' '}
                  <span className="text-blue-400 font-mono">souvikpanja582@gmail.com</span>
                  {' '}for review and action.
                </p>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
