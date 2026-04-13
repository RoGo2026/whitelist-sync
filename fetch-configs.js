const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  console.log('Открываем сайт...');
  await page.goto('https://ryzgames31.github.io/UWB/', { waitUntil: 'networkidle' });

  console.log('Нажимаем "Начать поиск конфигов"...');
  await page.getByRole('button', { name: /Начать поиск конфигов/i }).click();

  console.log('Ждём 90 секунд (поиск и проверка конфигов)...');
  await page.waitForTimeout(90000);

  console.log('Ожидаем появления кнопки скачивания...');
  await page.waitForSelector('button:has-text("Скачать конфиги")', { timeout: 30000 });

  console.log('Скачиваем конфиги...');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: /Скачать конфиги/i }).click();
  const download = await downloadPromise;

  await download.saveAs('uwb-configs.txt');
  console.log('Файл uwb-configs.txt успешно сохранён');

  await browser.close();
})().catch(err => {
  console.error('Ошибка:', err);
  process.exit(1);
});
