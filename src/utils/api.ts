/**
 * Utility functions for resilient API communication with LocalEDR backend.
 */

export async function safeFetchJson<T>(url: string, fallback?: T, options?: RequestInit): Promise<T> {
  try {
    const res = await fetch(url, options);
    if (!res.ok) {
      console.warn(`[LocalEDR] HTTP ${res.status} from ${url}`);
      return fallback as T;
    }
    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      console.warn(`[LocalEDR] Non-JSON content-type (${contentType}) from ${url}`);
      return fallback as T;
    }
    const data = await res.json();
    return data as T;
  } catch (err) {
    console.warn(`[LocalEDR] Network error fetching ${url}:`, err);
    return fallback as T;
  }
}
