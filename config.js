// إعدادات عامة (آمنة للعرض في المتصفح). لا تضع service_role key هنا أبداً.
// - لو شغّلت الموقع عبر uvicorn أو Render: اترك القيم فاضية، وهيتجلب كل شيء تلقائياً.
// - لو فتحت index.html مباشرة أو استضفت الواجهة منفصلة: املأ القيم التالية.
window.APP_CONFIG = {
  supabaseUrl: "httos://irvwksdqxyvlakrxfcuu.supabase.co",      // مثال: https://xxxx.supabase.co
  supabaseAnonKey: "sb_publishable_Q47XTjAVK_epbSYx7TOOxg_7IkUhVLP",  // anon public key
  apiBase: ""           // رابط الباك إند، مثال: https://smm-panel.onrender.com  (فاضي لو نفس الدومين)
};
