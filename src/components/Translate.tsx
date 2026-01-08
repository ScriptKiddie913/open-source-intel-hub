import { useEffect } from 'react';

export default function Translate() {
  useEffect(() => {
    // Ensure Google Translate popups and banners remain hidden
    const hideGoogleElements = () => {
      // Hide banner frame
      const banners = document.querySelectorAll('.goog-te-banner-frame, .skiptranslate iframe');
      banners.forEach((banner) => {
        if (banner instanceof HTMLElement) {
          banner.style.display = 'none';
          banner.style.visibility = 'hidden';
        }
      });

      // Remove top spacing
      document.body.style.top = '0';
      document.body.style.position = 'static';

      // Hide tooltips and balloons
      const popups = document.querySelectorAll('#goog-gt-tt, .goog-te-balloon-frame, .goog-tooltip');
      popups.forEach((popup) => {
        if (popup instanceof HTMLElement) {
          popup.style.display = 'none';
          popup.style.visibility = 'hidden';
        }
      });
    };

    // Run immediately
    hideGoogleElements();

    // Set up observer to catch dynamically added elements
    const observer = new MutationObserver((mutations) => {
      mutations.forEach(() => {
        hideGoogleElements();
      });
    });

    // Observe the entire document for changes
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style', 'class']
    });

    // Also run periodically as backup
    const interval = setInterval(hideGoogleElements, 500);

    // Cleanup
    return () => {
      observer.disconnect();
      clearInterval(interval);
    };
  }, []);

  // This component doesn't render anything visible
  // The Google Translate element is rendered in index.html
  return null;
}

// Export utility function to change language programmatically (optional)
export const changeLanguage = (langCode: string) => {
  const select = document.querySelector('.goog-te-combo') as HTMLSelectElement;
  if (select) {
    select.value = langCode;
    select.dispatchEvent(new Event('change'));
  }
};

// Export function to get current language (optional)
export const getCurrentLanguage = (): string => {
  const select = document.querySelector('.goog-te-combo') as HTMLSelectElement;
  return select ? select.value : 'en';
};
