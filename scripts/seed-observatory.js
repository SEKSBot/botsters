#!/usr/bin/env node

/**
 * Seed Observatory Script
 * Runs adversarial test cases through the scanner and logs results
 * Usage: node scripts/seed-observatory.js [endpoint]
 */

const fs = require('fs');
const path = require('path');

const endpoint = process.argv[2] || 'http://localhost:8787';
const testDir = path.join(__dirname, '..', 'tests', 'adversarial');

async function seedObservatory() {
  console.log('🔬 Seeding Observatory with adversarial test cases...');
  console.log(`📡 Endpoint: ${endpoint}`);
  
  // Read all test files
  const testFiles = fs.readdirSync(testDir)
    .filter(file => file.endsWith('.txt'))
    .sort();
  
  console.log(`📁 Found ${testFiles.length} test cases`);
  
  const results = [];
  
  for (const file of testFiles) {
    const filePath = path.join(testDir, file);
    const content = fs.readFileSync(filePath, 'utf8').trim();
    const testName = file.replace('.txt', '');
    
    console.log(`⚡ Testing ${testName}...`);
    
    try {
      const response = await fetch(`${endpoint}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: content })
      });
      
      if (!response.ok) {
        console.error(`❌ Failed ${testName}: ${response.status} ${response.statusText}`);
        continue;
      }
      
      const scanResult = await response.json();
      results.push({
        test: testName,
        content: content.slice(0, 100) + (content.length > 100 ? '...' : ''),
        heuristic_score: scanResult.heuristic.score,
        heuristic_matches: scanResult.heuristic.matches,
        ai_result: scanResult.ai,
        combined_score: scanResult.combined_score,
        clean: scanResult.heuristic.clean && (!scanResult.ai?.is_injection)
      });
      
      console.log(`   📊 Score: ${scanResult.combined_score.toFixed(2)} | Clean: ${scanResult.heuristic.clean} | Matches: ${scanResult.heuristic.matches.length}`);
      
      // Brief delay to avoid overwhelming the endpoint
      await new Promise(resolve => setTimeout(resolve, 100));
      
    } catch (error) {
      console.error(`❌ Error testing ${testName}:`, error.message);
    }
  }
  
  // Summary report
  console.log('\n🎯 Observatory Seeding Summary');
  console.log('================================');
  console.log(`📝 Total tests: ${results.length}`);
  console.log(`💉 Detected as injection: ${results.filter(r => !r.clean).length}`);
  console.log(`✅ Passed as clean: ${results.filter(r => r.clean).length}`);
  console.log(`🔥 High confidence (>0.7): ${results.filter(r => r.combined_score > 0.7).length}`);
  
  const avgScore = results.length > 0 
    ? (results.reduce((sum, r) => sum + r.combined_score, 0) / results.length).toFixed(3)
    : '0';
  console.log(`📈 Average score: ${avgScore}`);
  
  // Top detections
  const topDetections = results
    .filter(r => !r.clean)
    .sort((a, b) => b.combined_score - a.combined_score)
    .slice(0, 5);
  
  if (topDetections.length > 0) {
    console.log('\n🚩 Top Detections:');
    topDetections.forEach((result, i) => {
      console.log(`${i + 1}. ${result.test} (${result.combined_score.toFixed(2)})`);
      console.log(`   "${result.content}"`);
    });
  }
  
  // Potential bypasses
  const bypasses = results.filter(r => r.clean && r.heuristic_matches.length === 0);
  if (bypasses.length > 0) {
    console.log('\n⚠️  Potential Bypasses (investigate):');
    bypasses.forEach(result => {
      console.log(`- ${result.test}: "${result.content}"`);
    });
  }
  
  console.log('\n✅ Observatory seeding complete!');
  console.log(`🔗 View results: ${endpoint}/observatory`);
}

seedObservatory().catch(console.error);