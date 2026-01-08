import { useState, useEffect } from 'react';
import { Languages } from 'lucide-react';
import { cn } from '@/lib/utils';

const languages = [
  { code: 'en', name: 'English', flag: '🇬🇧' },
  { code: 'es', name: 'Español', flag: '🇪🇸' },
  { code: 'fr', name: 'Français', flag: '🇫🇷' },
  { code: 'de', name: 'Deutsch', flag: '🇩🇪' },
  { code: 'hi', name: 'हिन्दी', flag: '🇮🇳' },
  { code: 'bn', name: 'বাংলা', flag: '🇧🇩' },
  { code: 'zh-CN', name: '中文', flag: '🇨🇳' },
  { code: 'ja', name: '日本語', flag: '🇯🇵' },
  { code: 'ko', name: '한국어', flag: '🇰🇷' },
  { code: 'ar', name: 'العربية', flag: '🇸🇦' },
  { code: 'ru', name: 'Русский', flag: '🇷🇺' },
  { code: 'pt', name: 'Português', flag: '🇵🇹' },
  { code: 'it', name: 'Italiano', flag: '🇮🇹' },
  { code: 'tr', name: 'Türkçe', flag: '🇹🇷' },
  { code: 'nl', name: 'Nederlands', flag: '🇳🇱' },
  { code: 'pl', name: 'Polski', flag: '🇵🇱' },
  { code: 'vi', name: 'Tiếng Việt', flag: '🇻🇳' },
  { code: 'th', name: 'ไทย', flag: '🇹🇭' },
];

const Translate = () => {
  const [currentLang, setCurrentLang] = useState('en');

  useEffect(() => {
    // Check current language from Google Translate
    const checkInterval = setInterval(() => {
      const select = document.querySelector('.goog-te-combo') as HTMLSelectElement;
      if (select && select.value) {
        setCurrentLang(select.value);
        clearInterval(checkInterval);
      }
    }, 500);

    return () => clearInterval(checkInterval);
  }, []);

  const handleLanguageChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const langCode = e.target.value;
    setCurrentLang(langCode);

    // Wait for Google Translate to load
    const interval = setInterval(() => {
      const googleSelect = document.querySelector('.goog-te-combo') as HTMLSelectElement;
      if (googleSelect) {
        clearInterval(interval);
        googleSelect.value = langCode;
        googleSelect.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }, 100);

    // Fallback timeout
    setTimeout(() => clearInterval(interval), 5000);
  };

  return (
    <div className="fixed top-4 right-4 z-50">
      <div className="relative">
        <div className={cn(
          "flex items-center gap-2 px-3 py-2 rounded-lg",
          "bg-gradient-to-br from-slate-900 to-slate-950",
          "border border-primary/30",
          "shadow-lg shadow-primary/20",
          "backdrop-blur-sm"
        )}>
          <Languages className="h-4 w-4 text-primary flex-shrink-0" />
          <select
            value={currentLang}
            onChange={handleLanguageChange}
            className={cn(
              "bg-transparent border-none outline-none",
              "text-sm font-medium text-primary",
              "cursor-pointer",
              "pr-2",
              "appearance-none"
            )}
            style={{
              backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2306b6d4' d='M6 9L1 4h10z'/%3E%3C/svg%3E")`,
              backgroundRepeat: 'no-repeat',
              backgroundPosition: 'right center',
              paddingRight: '20px'
            }}
          >
            {languages.map((lang) => (
              <option 
                key={lang.code} 
                value={lang.code}
                className="bg-slate-900 text-foreground"
              >
                {lang.flag} {lang.name}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
};

export default Translate;

  return (
    <div className="fixed top-4 right-4 z-50">
      <div className="relative">
        <div className={cn(
          "flex items-center gap-2 px-3 py-2 rounded-lg",
          "bg-gradient-to-br from-slate-900 to-slate-950",
          "border border-primary/30",
          "shadow-lg shadow-primary/20",
          "backdrop-blur-sm"
        )}>
          <Languages className="h-4 w-4 text-primary flex-shrink-0" />
          <select
            value={currentLang}
            onChange={handleLanguageChange}
            className={cn(
              "bg-transparent border-none outline-none",
              "text-sm font-medium text-primary",
              "cursor-pointer",
              "pr-2",
              "appearance-none"
            )}
            style={{
              backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2306b6d4' d='M6 9L1 4h10z'/%3E%3C/svg%3E")`,
              backgroundRepeat: 'no-repeat',
              backgroundPosition: 'right center',
              paddingRight: '20px'
            }}
          >
            {languages.map((lang) => (
              <option 
                key={lang.code} 
                value={lang.code}
                className="bg-slate-900 text-foreground"
              >
                {lang.flag} {lang.name}
              </option>
            ))}
          </select>
        </div>
      </div>
    </div>
  );
};

export default Translate;

