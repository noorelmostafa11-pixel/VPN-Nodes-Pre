# VPN-Nodes-Pre

مستودع مستقل لتجهيز مرشحي بروتوكولات VPN قبل فحص Xray على السيرفرين.

## المخرجات
ناتج العقد يتكون من أربعة ملفات فقط:

- `output/protocols/vless.txt`
- `output/protocols/vmess.txt`
- `output/protocols/trojan.txt`
- `output/protocols/shadowsocks.txt`

## طريقة العمل
الكود والمصادر الموجودة داخل هذا المستودع مأخوذة من مرحلة إعداد المرشحين في الريبو العام عند المرجع:

`2e31b6ff3288c8141f0dd0054d43a6314c2021d7`

كل دورة تعمل داخل هذا المستودع وحده:

1. جمع المصادر من `sources/`.
2. نفس parsing.
3. قبول المنفذين 80 و443 فقط.
4. نفس source freshness.
5. نفس `xray_connection_equivalent` dedup.
6. فحص TCP مرة واحدة لكل `host:port`.
7. إعادة الإعدادات المميزة التي نجح endpoint الخاص بها.
8. تقسيمها إلى الملفات الأربعة أعلاه.

لا يتم تشغيل Xray هنا. فحص Xray النهائي يبقى على السيرفرين.

مجلد `state/` ليس ناتج عقد؛ يحتفظ فقط بحالة fallback/freshness التي يحتاجها المجمع بين الدورات.
