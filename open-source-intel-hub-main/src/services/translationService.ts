// src/services/translationService.ts
interface TranslationCache {
  [key: string]: { [text: string]: string };
}

const translationCache: TranslationCache = {};
const BATCH_SIZE = 50;
const RATE_LIMIT_DELAY = 100;

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

export async function translateText(text: string, targetLang: string): Promise<string> {
  if (!text.trim() || targetLang === 'en') return text;
  
  const cacheKey = `${targetLang}:${text}`;
  if (translationCache[targetLang]?.[text]) {
    return translationCache[targetLang][text];
  }

  try {
    // Use MyMemory Translation API (free, no key required)
    const response = await fetch(
      `https://api.mymemory.translated.net/get?q=${encodeURIComponent(text)}&langpair=en|${targetLang}`
    );
    
    const data = await response.json();
    const translated = data.responseData?.translatedText || text;
    
    if (!translationCache[targetLang]) {
      translationCache[targetLang] = {};
    }
    translationCache[targetLang][text] = translated;
    
    return translated;
  } catch (error) {
    console.error('Translation error:', error);
    return text;
  }
}

export async function translateBatch(texts: string[], targetLang: string): Promise<Map<string, string>> {
  const results = new Map<string, string>();
  const uncachedTexts = texts.filter(text => {
    if (translationCache[targetLang]?.[text]) {
      results.set(text, translationCache[targetLang][text]);
      return false;
    }
    return true;
  });

  for (let i = 0; i < uncachedTexts.length; i += BATCH_SIZE) {
    const batch = uncachedTexts.slice(i, i + BATCH_SIZE);
    await Promise.all(
      batch.map(async (text) => {
        const translated = await translateText(text, targetLang);
        results.set(text, translated);
      })
    );
    await sleep(RATE_LIMIT_DELAY);
  }

  return results;
}

interface TextNode {
  node: Node;
  originalText: string;
}

const translatedNodes = new WeakMap<Node, string>();
const excludeSelectors = ['script', 'style', 'code', 'pre', 'iframe'];

export function getTranslatableTextNodes(root: Element = document.body): TextNode[] {
  const textNodes: TextNode[] = [];
  const walker = document.createTreeWalker(
    root,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode: (node) => {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        
        // Skip excluded elements
        if (excludeSelectors.some(sel => parent.closest(sel))) {
          return NodeFilter.FILTER_REJECT;
        }
        
        // Skip empty or whitespace-only text
        const text = node.textContent?.trim();
        if (!text || text.length < 2) {
          return NodeFilter.FILTER_REJECT;
        }
        
        return NodeFilter.FILTER_ACCEPT;
      }
    }
  );

  let currentNode: Node | null;
  while ((currentNode = walker.nextNode())) {
    textNodes.push({
      node: currentNode,
      originalText: currentNode.textContent || ''
    });
  }

  return textNodes;
}

export async function translatePage(targetLang: string, onProgress?: (progress: number) => void) {
  if (targetLang === 'en') {
    // Restore original text
    const textNodes = getTranslatableTextNodes();
    textNodes.forEach(({ node }) => {
      const original = translatedNodes.get(node);
      if (original && node.textContent !== original) {
        node.textContent = original;
      }
    });
    return;
  }

  const textNodes = getTranslatableTextNodes();
  const uniqueTexts = Array.from(new Set(textNodes.map(n => n.originalText.trim())));
  
  let processed = 0;
  const total = uniqueTexts.length;

  for (let i = 0; i < uniqueTexts.length; i += BATCH_SIZE) {
    const batch = uniqueTexts.slice(i, i + BATCH_SIZE);
    const translations = await translateBatch(batch, targetLang);
    
    // Apply translations
    textNodes.forEach(({ node, originalText }) => {
      const trimmed = originalText.trim();
      const translated = translations.get(trimmed);
      if (translated && translated !== trimmed) {
        // Store original if not stored
        if (!translatedNodes.has(node)) {
          translatedNodes.set(node, originalText);
        }
        // Apply translation preserving whitespace
        const leading = originalText.match(/^\s*/)?.[0] || '';
        const trailing = originalText.match(/\s*$/)?.[0] || '';
        node.textContent = leading + translated + trailing;
      }
    });
    
    processed += batch.length;
    onProgress?.(Math.round((processed / total) * 100));
    
    await sleep(RATE_LIMIT_DELAY);
  }

  onProgress?.(100);
}

export function clearTranslationCache() {
  Object.keys(translationCache).forEach(key => delete translationCache[key]);
}

export function saveLanguagePreference(lang: string) {
  localStorage.setItem('preferred_language', lang);
}

export function getLanguagePreference(): string {
  return localStorage.getItem('preferred_language') || 'en';
}
