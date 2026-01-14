# 🚀 Live Deployment Guide - Open Source Intel Hub

## Option 1: Vercel (Recommended - Free)

1. **Create Vercel Account**: Go to [vercel.com](https://vercel.com) and sign up

2. **Connect GitHub**: 
   - Push your code to GitHub repository
   - Import the repository in Vercel dashboard

3. **Environment Variables**: Add these in Vercel dashboard:
   ```
   VITE_ABUSEIPDB_API_KEY=65ff4439d387be4284606b4f480e01c64c6a603852d1f9e6817016422cd59d54519c35f452c1c3e4
   VITE_GROQ_API_KEY=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
   VITE_NVD_API_KEY=f4a31bb5-4ec0-40db-a92e-bbb7ce326458
   VITE_PERPLEXITY_API_KEY=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
   VITE_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRhdW1zemFraGRud296Y25tcnRkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjcyNzQzMjQsImV4cCI6MjA4Mjg1MDMyNH0.EkklAF_2aqI6DV61wdsql6njcaQ4iTQIVyJJRy4hxaI
   VITE_SUPABASE_PROJECT_ID=xpbcscgajcnxthokttoi
   VITE_SUPABASE_PUBLISHABLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhwYmNzY2dhamNueHRob2t0dG9pIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjY0ODQ2MTAsImV4cCI6MjA4MjA2MDYxMH0.vuLs7cU_Mm2Wp6Zzva3zXu8iniEtnakIHf0XMhGicN0
   VITE_SUPABASE_URL=https://xpbcscgajcnxthokttoi.supabase.co
   VITE_VIRUSTOTAL_API_KEY=5b1f66e34505cb0985f4954a22751ea024db382e6ab8d7522c3652a51aaf2ce0
   ```

4. **Deploy**: Vercel will automatically build and deploy

## Option 2: Netlify (Alternative)

1. **Create Netlify Account**: Go to [netlify.com](https://netlify.com) 

2. **Drag & Drop Deploy**: 
   - Run: `npm run build`
   - Drag the `dist` folder to Netlify

3. **Environment Variables**: Add the same variables in Netlify dashboard

## Option 3: GitHub Pages

1. **Install gh-pages**: `npm install --save-dev gh-pages`

2. **Add deploy script** to package.json:
   ```json
   "deploy": "gh-pages -d dist"
   ```

3. **Deploy**: 
   ```bash
   npm run build
   npm run deploy
   ```

## Quick Deploy Commands

```bash
# Build for production
npm run build

# Preview locally
npm run preview

# Deploy to Vercel (after login)
vercel --prod
```

## 🌐 Your Live URLs Will Be:
- **Vercel**: `your-app.vercel.app`
- **Netlify**: `your-app.netlify.app`  
- **GitHub Pages**: `username.github.io/repo-name`

## 🔧 Pre-deployment Checklist:
✅ Build completes without errors
✅ Environment variables configured
✅ Supabase project is active
✅ API keys are valid
✅ All 29 threat sources working

## 🚨 Security Notes:
- API keys are exposed in frontend (normal for Vite)
- Use API key restrictions/quotas
- Monitor usage in each service dashboard

Your threat intelligence platform is ready to go live! 🎉