#!/usr/bin/env node
// puppeteer-wrapper.js v2.0 - Universal Puppeteer wrapper for CTF tools with parallel processing
const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const DEBUG = process.env.DEBUG === 'true';

// ==================== BROWSER POOL MANAGER ====================
class BrowserPool {
    constructor(poolSize = 3) {
        this.poolSize = poolSize;
        this.browsers = [];
        this.available = [];
        this.queue = [];
        this.initialized = false;
        this.stats = {
            totalLaunched: 0,
            totalAcquired: 0,
            totalReleased: 0
        };
    }
    
    async init() {
        if (this.initialized) return;
        
        console.error(`🚀 Initializing browser pool with ${this.poolSize} instances...`);
        
        for (let i = 0; i < this.poolSize; i++) {
            try {
                const browser = await puppeteer.launch({
                    headless: 'new',
                    args: [
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-features=IsolateOrigins,site-per-process',
                        '--window-size=1280,800'
                    ],
                    timeout: 30000
                });
                this.browsers.push(browser);
                this.available.push(browser);
                this.stats.totalLaunched++;
            } catch (error) {
                console.error(`Failed to launch browser ${i}:`, error.message);
            }
        }
        
        this.initialized = true;
        console.error(`✅ Browser pool ready: ${this.browsers.length}/${this.poolSize} browsers`);
    }
    
    async acquire() {
        if (!this.initialized) await this.init();
        
        return new Promise((resolve) => {
            if (this.available.length > 0) {
                const browser = this.available.pop();
                this.stats.totalAcquired++;
                resolve(browser);
            } else {
                this.queue.push(resolve);
            }
        });
    }
    
    release(browser) {
        this.available.push(browser);
        this.stats.totalReleased++;
        if (this.queue.length > 0) {
            const nextResolve = this.queue.shift();
            nextResolve(this.available.pop());
        }
    }
    
    async closeAll() {
        console.error('🛑 Closing all browsers...');
        for (const browser of this.browsers) {
            try {
                await browser.close();
            } catch (error) {
                // Ignore close errors
            }
        }
        this.browsers = [];
        this.available = [];
        this.queue = [];
        this.initialized = false;
    }
    
    getStats() {
        return {
            ...this.stats,
            available: this.available.length,
            inUse: this.browsers.length - this.available.length,
            queueLength: this.queue.length
        };
    }
}

// Create a singleton instance
const browserPool = new BrowserPool(process.env.PUPPETEER_POOL_SIZE || 5);

// ==================== PATTERN MATCHING ====================
async function checkWithPatterns(content, patternFile = null) {
    if (!patternFile || !fs.existsSync(patternFile)) {
        // Default patterns for JavaScript detection
        const defaultPatterns = [
            '<noscript>',
            'you need to enable javascript',
            'enable JavaScript',
            'root.*></div>',
            'static/js/',
            'webpack',
            '__NEXT_DATA__',
            'react-root',
            'ng-',
            'vue',
            'angular',
            'script.*defer',
            'application/json.*src'
        ];
        
        const patternStr = defaultPatterns.join('|');
        const regex = new RegExp(patternStr, 'i');
        return regex.test(content);
    }
    
    try {
        const patterns = fs.readFileSync(patternFile, 'utf8')
            .split('\n')
            .filter(line => line.trim() && !line.startsWith('#'))
            .map(pattern => pattern.trim());
        
        if (patterns.length === 0) {
            return checkWithPatterns(content); // Use defaults
        }
        
        const patternStr = patterns.join('|');
        const regex = new RegExp(patternStr, 'i');
        return regex.test(content);
    } catch (error) {
        console.error(`Error reading pattern file: ${error.message}`);
        return checkWithPatterns(content); // Use defaults
    }
}

// ==================== MAIN WRAPPER CLASS ====================
class PuppeteerWrapper {
    constructor(options = {}) {
        this.options = {
            headless: 'new',
            timeout: 30000,
            viewport: { width: 1280, height: 800 },
            poolSize: 5,
            ...options
        };
        this.puppeteerVersion = this.getPuppeteerVersion();
    }
    
    getPuppeteerVersion() {
        try {
            const pkg = require('puppeteer/package.json');
            return pkg.version;
        } catch {
            return 'unknown';
        }
    }
    
    async delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // ==================== SINGLE URL FETCH ====================
    async fetch(url, customHeaders = {}, method = 'GET', data = null) {
        const browser = await browserPool.acquire();
        
        try {
            const page = await browser.newPage();
            
            // Set custom headers
            if (Object.keys(customHeaders).length > 0) {
                await page.setExtraHTTPHeaders(customHeaders);
            }
            
            // Set viewport
            await page.setViewport(this.options.viewport);
            
            // Navigate
            if (method === 'GET') {
                await page.goto(url, { 
                    waitUntil: 'networkidle2', 
                    timeout: this.options.timeout 
                });
            } else if (method === 'POST' && data) {
                await page.goto(url, { waitUntil: 'domcontentloaded' });
                // POST handling would go here
            }
            
            // Wait for JavaScript execution
            await this.delay(800);
            
            // Get the fully rendered content
            const content = await page.content();
            const title = await page.title();
            
            // Capture status
            let statusCode = 200;
            let finalUrl = url;
            
            try {
                const response = await page.goto(url, { waitUntil: 'load', timeout: 500 });
                if (response) {
                    statusCode = response.status();
                    finalUrl = response.url();
                }
            } catch {
                // Use defaults if we can't get response
            }
            
            await page.close();
            
            return {
                status: statusCode,
                url: finalUrl,
                title: title,
                headers: {},
                body: content,
                length: content.length,
                rendered: true,
                success: true
            };
            
        } catch (error) {
            return {
                status: 500,
                url: url,
                title: '',
                error: error.message,
                body: '',
                rendered: false,
                success: false
            };
        } finally {
            browserPool.release(browser);
        }
    }
    
    // ==================== PARALLEL FETCH ====================
    async fetchParallel(urls, customHeaders = {}, concurrency = null) {
        const actualConcurrency = concurrency || this.options.poolSize;
        
        // Ensure pool is initialized with desired concurrency
        browserPool.poolSize = actualConcurrency;
        await browserPool.init();
        
        const results = {};
        const startTime = Date.now();
        
        console.error(`📊 Processing ${urls.length} URLs with ${actualConcurrency} concurrent browsers`);
        
        // Process URLs in parallel batches
        const processUrl = async (url, index) => {
            const browser = await browserPool.acquire();
            
            try {
                const page = await browser.newPage();
                
                // Set custom headers
                if (Object.keys(customHeaders).length > 0) {
                    await page.setExtraHTTPHeaders(customHeaders);
                }
                
                await page.setViewport({ width: 1280, height: 800 });
                
                let statusCode = 200;
                let finalUrl = url;
                
                try {
                    const response = await page.goto(url, { 
                        waitUntil: 'networkidle2', 
                        timeout: 15000 
                    });
                    
                    if (response) {
                        statusCode = response.status();
                        finalUrl = response.url();
                    }
                } catch (navError) {
                    statusCode = 500;
                }
                
                // Wait for JavaScript
                await this.delay(500);
                
                const content = await page.content();
                const title = await page.title();
                
                await page.close();
                
                results[url] = {
                    status: statusCode,
                    url: finalUrl,
                    title: title,
                    body: content,
                    length: content.length,
                    rendered: true,
                    success: statusCode === 200,
                    index: index
                };
                
                if (DEBUG) {
                    console.error(`  [${index}] ${url} → ${statusCode} (${content.length} bytes)`);
                }
                
            } catch (error) {
                results[url] = {
                    status: 500,
                    url: url,
                    error: error.message,
                    body: '',
                    rendered: false,
                    success: false,
                    index: index
                };
            } finally {
                browserPool.release(browser);
            }
        };
        
        // Create batches
        const batches = [];
        for (let i = 0; i < urls.length; i += actualConcurrency) {
            batches.push(urls.slice(i, i + actualConcurrency));
        }
        
        // Process batches
        let processed = 0;
        for (const batch of batches) {
            const batchPromises = batch.map((url, idx) => processUrl(url, processed + idx));
            await Promise.all(batchPromises);
            processed += batch.length;
            
            if (DEBUG) {
                console.error(`  Batch progress: ${processed}/${urls.length} (${Math.round((processed/urls.length)*100)}%)`);
            }
        }
        
        const endTime = Date.now();
        console.error(`✅ Parallel fetch completed in ${(endTime - startTime)/1000}s`);
        console.error(`📈 Pool stats:`, browserPool.getStats());
        
        return results;
    }
    
    // ==================== JS DETECTION ====================
    async testJavaScriptRequired(url, patternFile = null) {
        const browser = await browserPool.acquire();
        
        try {
            const page = await browser.newPage();
            
            // Disable JavaScript for the test
            await page.setJavaScriptEnabled(false);
            
            try {
                await page.goto(url, { 
                    waitUntil: 'domcontentloaded', 
                    timeout: 5000 
                });
                
                // Wait a bit
                await this.delay(500);
                
                const content = await page.content();
                
                // Check with patterns
                const needsJS = await checkWithPatterns(content, patternFile);
                
                await page.close();
                return needsJS;
                
            } catch (error) {
                await page.close();
                return true; // If navigation fails without JS, it probably needs JS
            }
        } finally {
            browserPool.release(browser);
        }
    }
    
    // ==================== BULK JS DETECTION ====================
    async testBulkJavaScriptRequired(urls, patternFile = null, concurrency = 5) {
        browserPool.poolSize = concurrency;
        await browserPool.init();
        
        const results = {};
        const urlChunks = [];
        
        // Split URLs into chunks
        for (let i = 0; i < urls.length; i += concurrency) {
            urlChunks.push(urls.slice(i, i + concurrency));
        }
        
        const processChunk = async (chunk) => {
            const chunkResults = {};
            
            for (const url of chunk) {
                try {
                    const needsJS = await this.testJavaScriptRequired(url, patternFile);
                    chunkResults[url] = needsJS;
                } catch (error) {
                    chunkResults[url] = true; // Assume needs JS on error
                }
            }
            
            return chunkResults;
        };
        
        // Process chunks in parallel
        for (const chunk of urlChunks) {
            const chunkResults = await processChunk(chunk);
            Object.assign(results, chunkResults);
        }
        
        return results;
    }
}

// ==================== COMMAND LINE INTERFACE ====================
async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
        console.log(`
Puppeteer Wrapper v2.0 - JavaScript-enabled fetching for CTF tools
Detected Puppeteer version: ${new PuppeteerWrapper().puppeteerVersion}

USAGE:
  node puppeteer-wrapper.js [OPTIONS] <URL|URL_FILE>

MODES:
  Single URL:    node puppeteer-wrapper.js <URL> [options]
  Batch file:    node puppeteer-wrapper.js --batch <FILE> [options]
  Multiple URLs: node puppeteer-wrapper.js <URL1> <URL2> <URL3> [options]

OPTIONS:
  -h, --help                   Show this help message
  -H, --header "Name: Value"   Add HTTP header (can be used multiple times)
  -o, --output FILE            Save response to file
  -c, --check-js               Check if page needs JavaScript
  -t, --timeout MS             Set timeout in milliseconds (default: 30000)
  -d, --debug                  Enable debug logging
  --no-headless                Run browser in visible mode
  
  PARALLEL PROCESSING:
  -p, --parallel N             Number of parallel browsers (default: 5)
  -b, --batch FILE             Process URLs from file (one per line)
  --concurrency N              Same as --parallel
  
  PATTERN MATCHING:
  --patterns FILE              Custom patterns file for JS detection
  --default-patterns           Use built-in patterns only
  
  BULK OPERATIONS:
  --bulk-check FILE            Check JS requirement for multiple URLs
  --save-raw DIR               Save raw responses to directory
  --summary                    Only show summary, not full content

EXAMPLES:
  # Single URL with headers
  node puppeteer-wrapper.js https://example.com -H "Cookie: session=abc" -o response.html
  
  # Check if URL needs JavaScript
  node puppeteer-wrapper.js https://example.com -c
  
  # Process multiple URLs in parallel
  node puppeteer-wrapper.js -b urls.txt -p 10 -o results.json
  
  # Bulk check JavaScript requirement
  node puppeteer-wrapper.js --bulk-check urls.txt --patterns mypatterns.txt
  
  # Fetch with custom patterns
  node puppeteer-wrapper.js https://example.com --patterns ctf-patterns.txt
        `);
        process.exit(0);
    }
    
    // Parse arguments
    const urls = [];
    const headers = {};
    let checkJs = false;
    let bulkCheck = false;
    let outputFile = null;
    let timeout = 30000;
    let headless = 'new';
    let parallel = 5;
    let batchFile = null;
    let patternFile = null;
    let saveRawDir = null;
    let summaryOnly = false;
    let defaultPatterns = false;
    
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        const nextArg = args[i + 1];
        
        if ((arg === '-H' || arg === '--header') && nextArg) {
            const [name, ...valueParts] = nextArg.split(': ');
            headers[name] = valueParts.join(': ');
            i++;
        } else if (arg === '-c' || arg === '--check-js') {
            checkJs = true;
        } else if (arg === '--bulk-check' && nextArg) {
            bulkCheck = true;
            batchFile = nextArg;
            i++;
        } else if ((arg === '-o' || arg === '--output') && nextArg) {
            outputFile = nextArg;
            i++;
        } else if ((arg === '-t' || arg === '--timeout') && nextArg) {
            timeout = parseInt(nextArg);
            i++;
        } else if (arg === '-d' || arg === '--debug') {
            process.env.DEBUG = 'true';
        } else if (arg === '--no-headless') {
            headless = false;
        } else if ((arg === '-p' || arg === '--parallel' || arg === '--concurrency') && nextArg) {
            parallel = parseInt(nextArg);
            i++;
        } else if ((arg === '-b' || arg === '--batch') && nextArg) {
            batchFile = nextArg;
            i++;
        } else if (arg === '--patterns' && nextArg) {
            patternFile = nextArg;
            i++;
        } else if (arg === '--default-patterns') {
            defaultPatterns = true;
        } else if (arg === '--save-raw' && nextArg) {
            saveRawDir = nextArg;
            i++;
        } else if (arg === '--summary') {
            summaryOnly = true;
        } else if (arg.startsWith('http')) {
            urls.push(arg);
        }
    }
    
    // If batch file specified, read URLs from it
    if (batchFile && fs.existsSync(batchFile)) {
        const fileUrls = fs.readFileSync(batchFile, 'utf8')
            .split('\n')
            .filter(line => line.trim() && (line.startsWith('http://') || line.startsWith('https://')));
        urls.push(...fileUrls);
    }
    
    if (urls.length === 0 && !bulkCheck) {
        console.error('❌ Error: No URLs provided');
        process.exit(1);
    }
    
    const wrapper = new PuppeteerWrapper({ 
        timeout,
        headless: headless,
        poolSize: parallel
    });
    
    try {
        // ==================== BULK JS CHECK ====================
        if (bulkCheck) {
            console.error(`🔍 Bulk checking ${urls.length} URLs for JavaScript requirement...`);
            
            const results = await wrapper.testBulkJavaScriptRequired(
                urls, 
                defaultPatterns ? null : patternFile,
                parallel
            );
            
            // Count results
            const jsCount = Object.values(results).filter(v => v).length;
            const nonJsCount = urls.length - jsCount;
            
            console.log(JSON.stringify({
                total: urls.length,
                needs_javascript: jsCount,
                no_javascript: nonJsCount,
                results: results
            }, null, 2));
            
            process.exit(0);
        }
        
        // ==================== SINGLE URL CHECK ====================
        if (checkJs && urls.length === 1) {
            const needsJS = await wrapper.testJavaScriptRequired(
                urls[0], 
                defaultPatterns ? null : patternFile
            );
            console.log(needsJS ? 'YES' : 'NO');
            process.exit(needsJS ? 0 : 1);
        }
        
        // ==================== SINGLE URL FETCH ====================
        if (urls.length === 1 && !checkJs) {
            console.error(`🌐 Fetching: ${urls[0]}`);
            const result = await wrapper.fetch(urls[0], headers);
            
            if (saveRawDir) {
                fs.mkdirSync(saveRawDir, { recursive: true });
                const filename = new URL(urls[0]).hostname.replace(/[^a-z0-9]/gi, '_') + '.html';
                fs.writeFileSync(path.join(saveRawDir, filename), result.body);
                console.error(`💾 Saved to: ${path.join(saveRawDir, filename)}`);
            }
            
            if (outputFile) {
                if (summaryOnly) {
                    fs.writeFileSync(outputFile, JSON.stringify({
                        url: result.url,
                        status: result.status,
                        title: result.title,
                        length: result.length,
                        rendered: result.rendered
                    }, null, 2));
                } else {
                    fs.writeFileSync(outputFile, result.body);
                }
                console.error(`💾 Output saved to: ${outputFile}`);
            } else {
                if (summaryOnly) {
                    console.log(JSON.stringify({
                        url: result.url,
                        status: result.status,
                        title: result.title,
                        length: result.length,
                        rendered: result.rendered
                    }, null, 2));
                } else {
                    console.log(result.body);
                }
            }
        }
        
        // ==================== PARALLEL FETCH ====================
        else if (urls.length > 1) {
            console.error(`🚀 Parallel fetching ${urls.length} URLs with ${parallel} browsers...`);
            
            const results = await wrapper.fetchParallel(urls, headers, parallel);
            
            // Save raw responses if requested
            if (saveRawDir) {
                fs.mkdirSync(saveRawDir, { recursive: true });
                for (const [url, result] of Object.entries(results)) {
                    if (result.success && result.body) {
                        const filename = new URL(url).hostname.replace(/[^a-z0-9]/gi, '_') + 
                                       '_' + Date.now() + '.html';
                        fs.writeFileSync(path.join(saveRawDir, filename), result.body);
                        result.savedFile = path.join(saveRawDir, filename);
                    }
                }
                console.error(`💾 Raw responses saved to: ${saveRawDir}`);
            }
            
            if (outputFile) {
                fs.writeFileSync(outputFile, JSON.stringify(results, null, 2));
                console.error(`💾 Results saved to: ${outputFile}`);
                
                // Show summary
                const successCount = Object.values(results).filter(r => r.success).length;
                const totalLength = Object.values(results).reduce((sum, r) => sum + r.length, 0);
                console.error(`📊 Summary: ${successCount}/${urls.length} successful, ${totalLength} total bytes`);
            } else {
                if (summaryOnly) {
                    const summary = {};
                    for (const [url, result] of Object.entries(results)) {
                        summary[url] = {
                            status: result.status,
                            title: result.title,
                            length: result.length,
                            rendered: result.rendered,
                            success: result.success
                        };
                    }
                    console.log(JSON.stringify(summary, null, 2));
                } else {
                    console.log(JSON.stringify(results, null, 2));
                }
            }
        }
        
    } catch (error) {
        console.error(`❌ Error: ${error.message}`);
        if (DEBUG) console.error(error.stack);
        process.exit(1);
    } finally {
        // Close browser pool
        await browserPool.closeAll();
    }
}

// ==================== ENTRY POINT ====================
if (require.main === module) {
    // Handle Ctrl+C gracefully
    process.on('SIGINT', async () => {
        console.error('\n🛑 Received SIGINT, shutting down...');
        await browserPool.closeAll();
        process.exit(0);
    });
    
    // Handle unhandled rejections
    process.on('unhandledRejection', (error) => {
        console.error('Unhandled rejection:', error.message);
        if (DEBUG) console.error(error.stack);
    });
    
    main().catch(error => {
        console.error(`Fatal error: ${error.message}`);
        if (DEBUG) console.error(error.stack);
        process.exit(1);
    });
}

module.exports = { PuppeteerWrapper, BrowserPool, checkWithPatterns };
