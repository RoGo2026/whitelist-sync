const { chromium } = require('playwright');

(async () => {
  console.log('Запуск браузера...');
  const browser = await chromium.launch({ 
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1280, height: 800 });

  console.log('Открываем сайт https://ryzgames31.github.io/UWB/');
  await page.goto('https://ryzgames31.github.io/UWB/', { 
    waitUntil: 'networkidle', 
    timeout: 60000 
  });

  console.log('Нажимаем кнопку "Начать поиск конфигов"...');
  await page.getByRole('button', { name: /Начать поиск конфигов/i }).click({ timeout: 10000 });

  console.log('Ожидаем 90 секунд завершения поиска...');
  await page.waitForTimeout(90000);

  console.log('Ожидаем кнопку "Скачать конфиги"...');
  await page.waitForSelector('button:has-text("Скачать конфиги")', { 
    timeout: 30000 
  });

  console.log('Скачиваем файл конфигов...');
  const downloadPromise = page.waitForEvent('download', { timeout: 15000 });
  await page.getByRole('button', { name: /Скачать конфиги/i }).click();
  
  const download = await downloadPromise;
  await download.saveAs('uwb-configs.txt');
  
  console.log('✅ Файл uwb-configs.txt успешно сохранён');
  await browser.close();
})().catch(err => {
  console.error('❌ Ошибка:', err.message);
  process.exit(1);
});
