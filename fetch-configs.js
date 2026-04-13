const { chromium } = require('playwright');
const fs = require('fs');

async function getConfigsFromSite(url, startButtonText, downloadButtonText, waitTime = 90000) {
  console.log(`Открываем сайт: ${url}`);
  const browser = await chromium.launch({ 
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1280, height: 800 });

  await page.goto(url, { waitUntil: 'networkidle', timeout: 60000 });

  console.log(`Нажимаем кнопку "${startButtonText}"...`);
  await page.getByRole('button', { name: new RegExp(startButtonText, 'i') }).click({ timeout: 15000 });

  console.log(`Ожидаем ${waitTime/1000} секунд...`);
  await page.waitForTimeout(waitTime);

  console.log(`Ожидаем появления кнопки скачивания "${downloadButtonText}"...`);
  await page.waitForSelector(`button:has-text("${downloadButtonText}")`, { timeout: 45000 });

  console.log(`Нажимаем кнопку скачивания...`);
  const downloadPromise = page.waitForEvent('download', { timeout: 30000 });
  await page.getByRole('button', { name: new RegExp(downloadButtonText, 'i') }).click();

  const download = await downloadPromise;
  const tempFile = `temp-${Date.now()}.txt`;
  await download.saveAs(tempFile);

  const content = fs.readFileSync(tempFile, 'utf8').trim();
  fs.unlinkSync(tempFile);
  await browser.close();

  console.log(`Получено ${content.split('\n').length} строк с сайта ${url}`);
  return content;
}

(async () => {
  let allConfigs = [];

  // === Сайт 1 ===
  console.log('=== Обработка первого сайта ===');
  const configs1 = await getConfigsFromSite(
    'https://ryzgames31.github.io/UWB/',
    'Начать поиск конфигов',
    'Скачать конфиги',
    60000
  );
  allConfigs.push(configs1);

  // === Сайт 2 ===
  console.log('\n=== Обработка второго сайта ===');
  const configs2 = await getConfigsFromSite(
    'https://obconfigs.vercel.app/',
    'Получить конфиги',
    'Скачать',           // основной текст кнопки
    120000               // увеличено до 120 секунд для второго сайта
  );
  allConfigs.push(configs2);

  // Объединяем
  const finalContent = allConfigs.filter(c => c.length > 0).join('\n').trim();
  fs.writeFileSync('mobile-whitelist-1.txt', finalContent);

  const totalLines = finalContent.split('\n').length;
  console.log(`\n✅ Успешно объединено и записано ${totalLines} строк в mobile-whitelist-1.txt`);

})().catch(err => {
  console.error('❌ Ошибка:', err.message);
  process.exit(1);
});
