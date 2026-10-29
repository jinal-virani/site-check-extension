export const T = (t, tone, extra = {}) => ({ t: String(t), tone, ...extra });
export const M = (t, extra = {}) => ({ t: String(t), mono: true, ...extra });
export const L = (t, href, extra = {}) => ({ t: String(t), href, ...extra });
export const res = (tone, summary, sections = []) => ({ tone, summary, sections });
