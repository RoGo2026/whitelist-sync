const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  console.log('Запуск браузера...');
  const browser = await chromium.launch({ 
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1280, height: 800 });

  console.log('Открываем сайт...');
  await page.goto('https://ryzgames31.github.io/UWB/', { 
    waitUntil: 'networkidle', 
    timeout: 60000 
  });

  console.log('Нажимаем "Начать поиск конфигов"...');
  await page.getByRole('button', { name: /Начать поиск конфигов/i }).click();

  console.log('Ожидаем 60 секунд...');
  await page.waitForTimeout(60000);

  console.log('Скачиваем конфиги...');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: /Скачать конфиги/i }).click();
  
  const download = await downloadPromise;
  await download.saveAs('uwb-configs.txt');

  const configsContent = fs.readFileSync('uwb-configs.txt', 'utf8');
  const lineCount = configsContent.trim().split('\n').length;

  fs.writeFileSync('mobile-whitelist-1.txt', configsContent);

  console.log(`✅ Успешно записано ${lineCount} строк в mobile-whitelist-1.txt`);

  fs.unlinkSync('uwb-configs.txt');
  await browser.close();
})().catch(err => {
  console.error('❌ Ошибка:', err.message);
  process.exit(1);
});
