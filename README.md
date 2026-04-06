# Kali Tools Automation & Report Hunter

Bu araç, Kali Linux araçlarını otomatik olarak çalıştıran ve masaüstünüzde düzenli raporlar (HTML ve metin) oluşturan güçlü bir Python uygulamasıdır.

## Özellikler
- **Otomatik Tarama**: Nmap, Nikto, SQLMap, Gobuster, Dirb ve Wfuzz araçlarını tek tıkla çalıştırır.
- **Canlı Log**: Tarama sürecini gerçek zamanlı olarak takip eder.
- **Detaylı Raporlama**: Masaüstünde her site için ayrı bir klasör oluşturur ve HTML formatında profesyonel raporlar sunar.
- **Türkçe Açıklama**: Tespit edilen güvenlik açıklarını (SQLi, XSS, CSRF vb.) Türkçe olarak açıklar ve çözüm önerileri sunar.

## Kullanım
1. Python yüklü olduğundan emin olun.
2. Gerekli kütüphaneleri yükleyin: `pip install requests beautifulsoup4`
3. Uygulamayı çalıştırın: `python last_pentester.py`
4. Hedef siteyi girin ve taramayı başlatın.

## Önemli Uyarı
Bu araç sadece eğitim ve yasal güvenlik testleri için tasarlanmıştır. Yetkisiz sistemlere yapılan saldırılar suçtur.
