const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
  console.log('Запуск браузера');
  
  const browser = await chromium.launch({ 
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page1 = await browser.newPage();
  const page2 = await browser.newPage();

  await page1.setViewportSize({ width: 1280, height: 800 });
  await page2.setViewportSize({ width: 1280, height: 800 });

  // Открываем оба сайта одновременно
  console.log('Открываем оба сайта...');
  await Promise.all([
    page1.goto('https://ryzgames31.github.io/UWB/', { waitUntil: 'networkidle', timeout: 60000 }),
    page2.goto('https://obconfigs.vercel.app/', { waitUntil: 'networkidle', timeout: 60000 })
  ]);

  // Нажимаем кнопки запуска параллельно
  console.log('Нажимаем кнопки запуска на обоих сайтах...');
  await Promise.all([
    page1.getByRole('button', { name: /Начать поиск конфигов/i }).click({ timeout: 15000 }).catch(() => {}),
    page2.getByRole('button', { name: /Получить конфиги/i }).click({ timeout: 15000 }).catch(() => {})
  ]);

  // Обработка предупреждающего окна только на втором сайте
  console.log('Проверяем и закрываем предупреждающее окно на втором сайте...');
  try {
    await page2.waitForSelector('button:has-text("Продолжить")', { timeout: 8000 });
    await page2.getByRole('button', { name: /Продолжить/i }).click({ timeout: 10000 });
    console.log('Кнопка "Продолжить" нажата.');
  } catch (e) {
    console.log('Окно подтверждения не найдено (возможно, не требуется).');
  }

  // Параллельное ожидание 120 секунд для обоих сайтов
  console.log('Ожидаем 120 секунд завершения поиска на обоих сайтах параллельно...');
  await Promise.all([
    page1.waitForTimeout(120000),
    page2.waitForTimeout(120000)
  ]);

  // Скачиваем конфиги параллельно
  console.log('Скачиваем конфиги с обоих сайтов...');

  const download1Promise = page1.waitForEvent('download', { timeout: 45000 });
  const download2Promise = page2.waitForEvent('download', { timeout: 45000 });

  await Promise.all([
    page1.getByRole('button', { name: /Скачать конфиги/i }).click().catch(() => {}),
    page2.getByRole('button', { name: /Скачать/i }).click().catch(() => {})
  ]);

  const [download1, download2] = await Promise.all([download1Promise, download2Promise]);

  await download1.saveAs('configs1.txt');
  await download2.saveAs('configs2.txt');

  // Объединяем результаты
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
