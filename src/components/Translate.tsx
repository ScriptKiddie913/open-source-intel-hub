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
    // Clear any existing translation on initial load
    document.cookie = 'googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    document.cookie = `googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=${window.location.hostname}`;
    localStorage.removeItem('googtrans');
  }, []);

  const handleLanguageChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const langCode = e.target.value;
    setCurrentLang(langCode);

    if (langCode === 'en') {
      // Clear translation and reload
      document.cookie = 'googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
      document.cookie = `googtrans=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=${window.location.hostname}`;
      localStorage.removeItem('googtrans');
      window.location.reload();
    } else {
      // Set Google Translate cookie
      const cookieVal = `/en/${langCode}`;
      document.cookie = `googtrans=${cookieVal}; path=/;`;
      document.cookie = `googtrans=${cookieVal}; path=/; domain=${window.location.hostname}`;
      localStorage.setItem('googtrans', cookieVal);
      window.location.reload();
    }
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

