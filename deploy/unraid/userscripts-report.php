<?php
// Read-only report on the User Scripts plugin, for unraid-agent. It is the forced command of the
// agent's SSH key (deploy/install-userscripts-access.sh), so the key can run nothing else.
// Prints one JSON object. Changes nothing.
//
// User Scripts discards each script's exit code, so the agent judges a run by its log: the plugin
// appends every run to /tmp/user.scripts/tmpScripts/<name>/log.txt between "Script Starting <date>"
// and "Script Finished <date>". Only the latest run of each script is read, from the end of the log.

const BASE = '/boot/config/plugins/user.scripts';
const TMP = '/tmp/user.scripts';
const TAIL_LINES = 30;
const MAX_HITS = 100;
const MAX_LINE = 400;
const MAX_SCAN = 16 << 20;  // read at most the last 16 MB of a run
// Lines worth sending; the agent decides which of them are errors.
const HINT = '/error|fail|fatal|denied|not found|no such|cannot|can\'t|unable|killed|traceback|exception|abort|refused|timed? ?out|segmentation|panic/i';
const STAMP = 'M d, Y  H:i.s';  // the plugin's date() format

function stamp(string $line): ?int {
  $d = DateTime::createFromFormat(STAMP, trim(preg_replace('/^Script (Starting|Finished) /', '', $line)));
  return $d ? $d->getTimestamp() : null;
}

function clip(string $line): string {
  return substr(rtrim($line, "\r\n"), 0, MAX_LINE);
}

function last_run(string $log): ?array {
  $size = filesize($log);
  $hit = exec('grep -a -b ' . escapeshellarg('^Script Starting ') . ' ' . escapeshellarg($log) . ' | tail -n 1');
  if (!$hit || !preg_match('/^(\d+):(.*)$/', $hit, $m)) return null;
  $offset = (int)$m[1];
  $run = ['started' => trim(substr($m[2], 16)), 'started_at' => stamp($m[2]), 'bytes' => $size - $offset,
          'finished' => null, 'finished_at' => null, 'hits' => [], 'hits_total' => 0, 'tail' => [], 'truncated' => false];
  $fh = fopen($log, 'rb');
  if (!$fh) return $run;
  if ($size - $offset > MAX_SCAN) {
    $run['truncated'] = true;
    fseek($fh, $size - MAX_SCAN);
    fgets($fh);  // skip the partial line
  } else {
    fseek($fh, $offset);
  }
  $tail = [];
  while (($line = fgets($fh)) !== false) {
    if (strncmp($line, 'Script Finished ', 16) === 0) {
      $run['finished'] = trim(substr($line, 16));
      $run['finished_at'] = stamp($line);
      continue;
    }
    if (strncmp($line, 'Script Starting ', 16) === 0 || strncmp($line, 'Full logs for this script', 25) === 0
        || trim($line) === '') continue;
    // rclone -P and similar redraw a line with \r: keep the last frame
    $parts = explode("\r", rtrim($line, "\r\n"));
    $line = end($parts);
    if (preg_match(HINT, $line)) {
      $run['hits_total']++;
      if (count($run['hits']) < MAX_HITS) $run['hits'][] = clip($line);
    }
    $tail[] = clip($line);
    if (count($tail) > TAIL_LINES) array_shift($tail);
  }
  fclose($fh);
  $run['tail'] = $tail;
  return $run;
}

$schedule = json_decode((string)@file_get_contents(BASE . '/schedule.json'), true);
$crontab = [];
exec('crontab -l 2>/dev/null', $lines);
foreach ($lines as $l) if (preg_match('#run-parts /etc/cron\.(hourly|daily|weekly|monthly)#', $l)) $crontab[] = $l;

$out = [
  'now' => time(),
  'timezone' => date_default_timezone_get(),
  'booted' => @filemtime(TMP . '/booted') ?: null,
  'crontab' => $crontab,
  'schedule' => is_array($schedule) ? array_values($schedule) : [],
  'scripts' => [],
];
foreach (glob(BASE . '/scripts/*', GLOB_ONLYDIR) as $dir) {
  if (!is_file("$dir/script")) continue;
  $name = basename($dir);
  $s = ['name' => $name, 'path' => "$dir/script", 'running' => null, 'log' => null];
  $pidfile = TMP . "/running/$name";
  if (is_file($pidfile)) {
    $pid = (int)trim((string)@file_get_contents($pidfile));
    $s['running'] = ['pid' => $pid, 'since' => filemtime($pidfile), 'alive' => $pid > 0 && is_dir("/proc/$pid")];
  }
  $log = TMP . "/tmpScripts/$name/log.txt";
  if (is_file($log)) $s['log'] = last_run($log);
  $out['scripts'][] = $s;
}
echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), "\n";
