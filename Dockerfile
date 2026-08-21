FROM node:18-alpine

# تعيين مجلد العمل
WORKDIR /app

# نسخ ملفات المشروع
COPY package*.json ./

# تثبيت المتطلبات
RUN npm install --production

# نسخ باقي الملفات
COPY . .

# إنشاء مجلدات التحميل
RUN mkdir -p downloads temp

# تعيين المنفذ
EXPOSE 3000

# تشغيل السيرفر
CMD ["node", "server_v2_with_dashboard.js"]
