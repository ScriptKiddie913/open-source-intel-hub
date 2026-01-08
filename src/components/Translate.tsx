import { useState } from 'react';
import { Languages } from 'lucide-react';
import { cn } from '@/lib/utils';

const languages = [
  { code: 'en', name: 'English', flag: '🇬🇧' },
  { code: 'es', name: 'Español', flag: '🇪🇸' },
  { code: 'fr', name: 'Français', flag: '🇫🇷' },
  { code: 'de', name: 'Deutsch', flag: '🇩🇪' },
  { code: 'hi', name: 'हिन्दी', flag: '🇮🇳' },
  { code: 'bn', name: 'বাংলা', flag: '🇧🇩' },
  { code: 'zh', name: '中文', flag: '🇨🇳' },
  { code: 'ja', name: '日本語', flag: '🇯🇵' },
  { code: 'ko', name: '한국어', flag: '🇰🇷' },
  { code: 'ar', name: 'العربية', flag: '🇸🇦' },
  { code: 'ru', name: 'Русский', flag: '🇷🇺' },
  { code: 'pt', name: 'Português', flag: '🇵🇹' },
  { code: 'it', name: 'Italiano', flag: '🇮🇹' },
  { code: 'tr', name: 'Türkçe', flag: '🇹🇷' },
];

const Translate = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [currentLang, setCurrentLang] = useState('en');

  const translatePage = (targetLang: string) => {
    const currentUrl = window.location.href;
    const googleTranslateUrl = `https://translate.google.com/translate?sl=auto&tl=${targetLang}&u=${encodeURIComponent(currentUrl)}`;
    window.location.href = googleTranslateUrl;
  };

  const handleLanguageSelect = (langCode: string) => {
    setCurrentLang(langCode);
    setIsOpen(false);
    if (langCode !== 'en') {
      translatePage(langCode);
    }
  };

  return (
    <div className="fixed top-4 right-4 z-50">
      <div className="relative">
        {/* Main Button */}
        <button
          onClick={() => setIsOpen(!isOpen)}
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-lg",
            "bg-gradient-to-br from-slate-900 to-slate-950",
            "border border-primary/30 hover:border-primary/60",
            "text-primary hover:text-primary-foreground",
            "shadow-lg shadow-primary/20 hover:shadow-primary/40",
            "transition-all duration-300",
            "backdrop-blur-sm"
          )}
        >
          <Languages className="h-4 w-4" />
          <span className="text-sm font-medium">
            {languages.find(l => l.code === currentLang)?.flag || '🌐'}
          </span>
        </button>

        {/* Dropdown Menu */}
        {isOpen && (
          <div className={cn(
            "absolute top-full right-0 mt-2 w-56",
            "bg-gradient-to-b from-slate-900 to-slate-950",
            "border border-primary/30 rounded-lg",
            "shadow-2xl shadow-primary/30",
            "backdrop-blur-md",
            "overflow-hidden"
          )}>
            <div className="p-2 border-b border-primary/20">
              <div className="flex items-center gap-2 px-2 py-1">
                <Languages className="h-3 w-3 text-primary" />
                <span className="text-xs font-semibold text-primary uppercase tracking-wider">
                  Select Language
                </span>
              </div>
            </div>
            
            <div className="max-h-96 overflow-y-auto scrollbar-thin scrollbar-thumb-primary/30 scrollbar-track-transparent">
              {languages.map((lang) => (
                <button
                  key={lang.code}
                  onClick={() => handleLanguageSelect(lang.code)}
                  className={cn(
                    "w-full flex items-center gap-3 px-4 py-2.5",
                    "text-left text-sm transition-all duration-200",
                    "hover:bg-primary/10 hover:text-primary",
                    currentLang === lang.code
                      ? "bg-primary/20 text-primary font-medium"
                      : "text-muted-foreground"
                  )}
                >
                  <span className="text-lg">{lang.flag}</span>
                  <span>{lang.name}</span>
                  {currentLang === lang.code && (
                    <span className="ml-auto text-primary">✓</span>
                  )}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Click outside to close */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => setIsOpen(false)}
        />
      )}
    </div>
  );
};

export default Translate;
