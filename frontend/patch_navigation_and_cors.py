import os

FRONTEND_DIR = "frontend"
files = ["index.html", "dashboard.html", "scanner.html", "login.html", "report.html"]

for file in files:
    path = os.path.join(FRONTEND_DIR, file)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Replace localhost:5000 with 127.0.0.1:5000
        content = content.replace("localhost:5000", "127.0.0.1:5000")
        
        # In index.html, fix buttons
        if file == "index.html":
            content = content.replace(
                '<button class="bg-primary text-background-dark px-6 py-2.5 rounded-lg font-bold text-sm hover:shadow-[0_0_20px_rgba(16,183,127,0.4)] transition-all flex items-center gap-2 mono-text">',
                '<button onclick="window.location.href=\'login.html\'" class="bg-primary text-background-dark px-6 py-2.5 rounded-lg font-bold text-sm hover:shadow-[0_0_20px_rgba(16,183,127,0.4)] transition-all flex items-center gap-2 mono-text">'
            )
            content = content.replace(
                '<button class="w-full sm:w-auto bg-primary text-background-dark px-8 py-4 rounded-xl font-bold text-lg hover:shadow-[0_0_30px_rgba(16,183,127,0.5)] transition-all flex items-center justify-center gap-3 mono-text">',
                '<button onclick="window.location.href=\'scanner.html\'" class="w-full sm:w-auto bg-primary text-background-dark px-8 py-4 rounded-xl font-bold text-lg hover:shadow-[0_0_30px_rgba(16,183,127,0.5)] transition-all flex items-center justify-center gap-3 mono-text">'
            )
            content = content.replace(
                '<button class="w-full sm:w-auto border border-slate-700 bg-slate-800/50 text-white px-8 py-4 rounded-xl font-bold text-lg hover:bg-slate-800 transition-all mono-text">',
                '<button onclick="window.location.href=\'scanner.html\'" class="w-full sm:w-auto border border-slate-700 bg-slate-800/50 text-white px-8 py-4 rounded-xl font-bold text-lg hover:bg-slate-800 transition-all mono-text">'
            )
            
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

print("HTML patches applied.")
