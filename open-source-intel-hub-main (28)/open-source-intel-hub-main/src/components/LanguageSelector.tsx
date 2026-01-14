import { useState, useEffect, useCallback } from 'react';
import { Globe, ChevronDown, Check } from 'lucide-react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

const LANGUAGES = [
  { code: 'en', name: 'English', nativeName: 'English' },
  { code: 'es', name: 'Spanish', nativeName: 'Español' },
  { code: 'fr', name: 'French', nativeName: 'Français' },
  { code: 'de', name: 'German', nativeName: 'Deutsch' },
  { code: 'hi', name: 'Hindi', nativeName: 'हिन्दी' },
  { code: 'bn', name: 'Bengali', nativeName: 'বাংলা' },
  { code: 'zh-CN', name: 'Chinese', nativeName: '中文' },
  { code: 'ja', name: 'Japanese', nativeName: '日本語' },
  { code: 'ko', name: 'Korean', nativeName: '한국어' },
  { code: 'ar', name: 'Arabic', nativeName: 'العربية' },
  { code: 'ru', name: 'Russian', nativeName: 'Русский' },
  { code: 'pt', name: 'Portuguese', nativeName: 'Português' },
  { code: 'it', name: 'Italian', nativeName: 'Italiano' },
  { code: 'tr', name: 'Turkish', nativeName: 'Türkçe' },
  { code: 'nl', name: 'Dutch', nativeName: 'Nederlands' },
  { code: 'pl', name: 'Polish', nativeName: 'Polski' },
  { code: 'vi', name: 'Vietnamese', nativeName: 'Tiếng Việt' },
  { code: 'th', name: 'Thai', nativeName: 'ไทย' },
];

// Cookie helpers
function setCookie(name: string, value: string, days: number = 365) {
  const expires = new Date(Date.now() + days * 864e5).toUTCString();
  document.cookie = `${name}=${encodeURIComponent(value)}; expires=${expires}; path=/; SameSite=Lax`;
}

function getCookie(name: string): string | null {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    return decodeURIComponent(parts.pop()?.split(';').shift() || '');
  }
  return null;
}

interface LanguageSelectorProps {
  className?: string;
  variant?: 'default' | 'compact';
}

export function LanguageSelector({ className, variant = 'default' }: LanguageSelectorProps) {
  const [selectedLang, setSelectedLang] = useState('en');
  const [isOpen, setIsOpen] = useState(false);
  const [isTranslating, setIsTranslating] = useState(false);

  // Apply translation using Google Translate
  const applyTranslation = useCallback((langCode: string) => {
    if (langCode === 'en') {
      // Reset to English - remove translation
      const frame = document.querySelector('.goog-te-banner-frame') as HTMLIFrameElement;
      if (frame) {
        const closeBtn = frame.contentDocument?.querySelector('.goog-close-link') as HTMLElement;
        closeBtn?.click();
      }
      
      // Also try setting cookie to reset
      document.cookie = 'googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      document.cookie = 'googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=' + window.location.hostname;
      
      // Reload to apply reset
      if (getCookie('preferred_language') !== 'en') {
        setCookie('preferred_language', 'en');
        window.location.reload();
      }
      return;
    }

    // Set Google Translate cookie
    const googleTranslateCookie = `/en/${langCode}`;
    document.cookie = `googtrans=${googleTranslateCookie}; path=/;`;
    document.cookie = `googtrans=${googleTranslateCookie}; path=/; domain=${window.location.hostname}`;

    // Try to trigger Google Translate widget
    const selectElement = document.querySelector('.goog-te-combo') as HTMLSelectElement;
    if (selectElement) {
      selectElement.value = langCode;
      selectElement.dispatchEvent(new Event('change', { bubbles: true }));
      setIsTranslating(false);
    } else {
      // If widget not ready, reload to apply translation
      setIsTranslating(true);
      setTimeout(() => {
        window.location.reload();
      }, 100);
    }
  }, []);

  // Load saved language on mount
  useEffect(() => {
    const savedLang = getCookie('preferred_language');
    if (savedLang && savedLang !== selectedLang) {
      setSelectedLang(savedLang);
    }
    
    // Check if Google Translate has been applied via cookie
    const googtrans = getCookie('googtrans');
    if (googtrans && savedLang && savedLang !== 'en') {
      // Ensure the widget applies the translation
      const checkAndApply = () => {
        const selectElement = document.querySelector('.goog-te-combo') as HTMLSelectElement;
        if (selectElement && selectElement.value !== savedLang) {
          selectElement.value = savedLang;
          selectElement.dispatchEvent(new Event('change', { bubbles: true }));
        }
      };
      
      // Try multiple times as widget loads asynchronously
      setTimeout(checkAndApply, 500);
      setTimeout(checkAndApply, 1500);
      setTimeout(checkAndApply, 3000);
    }
  }, [selectedLang]);

  const handleLanguageChange = (langCode: string) => {
    setSelectedLang(langCode);
    setCookie('preferred_language', langCode);
    setIsOpen(false);
    applyTranslation(langCode);
  };

  const currentLang = LANGUAGES.find(l => l.code === selectedLang) || LANGUAGES[0];

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size={variant === 'compact' ? 'sm' : 'default'}
          className={cn(
            "flex items-center gap-2 text-slate-300 hover:text-white hover:bg-slate-800/50",
            variant === 'compact' && "px-2",
            isTranslating && "opacity-50 pointer-events-none",
            className
          )}
          disabled={isTranslating}
        >
          <Globe className={cn("h-4 w-4", variant === 'compact' && "h-3.5 w-3.5")} />
          <span className={cn("hidden sm:inline", variant === 'compact' && "text-xs")}>
            {currentLang.nativeName}
          </span>
          <ChevronDown className={cn("h-3 w-3", isOpen && "rotate-180", "transition-transform")} />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        className="w-56 max-h-80 overflow-y-auto bg-slate-900 border-slate-700 z-[9999]"
      >
        {LANGUAGES.map((lang) => (
          <DropdownMenuItem
            key={lang.code}
            onClick={() => handleLanguageChange(lang.code)}
            className={cn(
              "flex items-center justify-between cursor-pointer",
              "hover:bg-slate-800 focus:bg-slate-800",
              selectedLang === lang.code && "bg-primary/10 text-primary"
            )}
          >
            <div className="flex flex-col">
              <span className="font-medium">{lang.nativeName}</span>
              <span className="text-xs text-muted-foreground">{lang.name}</span>
            </div>
            {selectedLang === lang.code && (
              <Check className="h-4 w-4 text-primary" />
            )}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
