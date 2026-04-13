const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  console.log('Запуск браузера и открытие двух сайтов параллельно...');
  
  const browser = await chromium.launch({ 
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  // Создаём две вкладки
  const page1 = await browser.newPage();  // Первый сайт
  const page2 = await browser.newPage();  // Второй сайт

  await page1.setViewportSize({ width: 1280, height: 800 });
  await page2.setViewportSize({ width: 1280, height: 800 });

  // Открываем оба сайта одновременно
  console.log('Открываем оба сайта...');
  await Promise.all([
    page1.goto('https://ryzgames31.github.io/UWB/', { waitUntil: 'networkidle', timeout: 60000 }),
    page2.goto('https://obconfigs.vercel.app/', { waitUntil: 'networkidle', timeout: 60000 })
  ]);

  // Нажимаем кнопки запуска почти одновременно
  console.log('Нажимаем кнопки запуска на обоих сайтах...');
  await Promise.all([
    page1.getByRole('button', { name: /Начать поиск конфигов/i }).click({ timeout: 15000 }),
    page2.getByRole('button', { name: /Получить конфиги/i }).click({ timeout: 15000 })
  ]);

  // Ждём 90 секунд параллельно для обоих сайтов
  console.log('Ожидаем 120 секунд завершения поиска на обоих сайтах...');
  await Promise.all([
    page1.waitForTimeout(120000),
    page2.waitForTimeout(120000)
  ]);

  // Скачиваем конфиги с обеих вкладок
  console.log('Скачиваем конфиги с обоих сайтов...');

  const download1Promise = page1.waitForEvent('download', { timeout: 30000 });
  const download2Promise = page2.waitForEvent('download', { timeout: 30000 });

  await Promise.all([
    page1.getByRole('button', { name: /Скачать конфиги/i }).click(),
    page2.getByRole('button', { name: /Скачать/i }).click()
  ]);

  const [download1, download2] = await Promise.all([download1Promise, download2Promise]);

  await download1.saveAs('configs1.txt');
  await download2.saveAs('configs2.txt');

  // Объединяем содержимое
  const content1 = fs.readFileSync('configs1.txt', 'utf8').trim();
  const content2 = fs.readFileSync('configs2.txt', 'utf8').trim();

  const finalContent = [content1, content2].filter(c => c.length > 0).join('\n').trim();
  fs.writeFileSync('mobile-whitelist-1.txt', finalContent);

  const totalLines = finalContent.split('\n').length;
  console.log(`✅ Успешно объединено и записано ${totalLines} строк в mobile-whitelist-1.txt`);

  // Очистка
  fs.unlinkSync('configs1.txt');
  fs.unlinkSync('configs2.txt');
  await browser.close();

})().catch(err => {
  console.error('❌ Ошибка:', err.message);
  process.exit(1);
});
