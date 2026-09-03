var test = require('tape');
var expand = require('..');

function repeat(str, n) {
  return new Array(n + 1).join(str);
}

function join(str, n, sep) {
  var parts = [];
  for (var i = 0; i < n; i++) {
    parts.push(str);
  }
  return parts.join(sep);
}

function totalLength(list) {
  return list.reduce(function (sum, s) { return sum + s.length; }, 0);
}

// Bypass of CVE-2026-14257's mitigation: each comma-separated alternative
// (`{alt,alt,...}`) is expanded independently, and `maxLength` only bounded
// each alternative's own output, not the running total accumulated across
// all of them. Many alternatives - each individually far under `maxLength` -
// could still sum to an unbounded intermediate array before the final
// `combine` call ever got a chance to truncate.
test('total length across comma alternatives is bounded', function (t) {
  var str = '{' + join('{1..5}', 1000, ',') + '}';
  var startTime = Date.now();
  var expanded = expand(str, { maxLength: 50 });
  var endTime = Date.now();

  var total = totalLength(expanded);
  t.ok(
    total <= 50,
    'Expected total length (' + total + ') to respect maxLength'
  );
  t.ok(expanded.length > 0, 'still returns a (truncated) result');
  t.ok(
    endTime - startTime < 500,
    'Expected time (' + (endTime - startTime) + 'ms) to be less than 500ms'
  );

  // Regression case from the report: 400 alternatives, each individually
  // bounded by maxLength but unbounded in aggregate before the fix.
  var part = '{' + repeat('0', 50) + '1..100000}';
  var bigStr = '{' + join(part, 400, ',') + '}';
  t.doesNotThrow(function () {
    var bigTotal = totalLength(expand(bigStr));
    t.ok(
      bigTotal <= 4000000,
      'Expected total length (' + bigTotal + ') to stay bounded'
    );
  });

  t.end();
});

// A padded sequence's element width follows the input, so generating all `max`
// elements before `combine` could discard them cost time proportional to
// `max * width` - a ~400KB input blocked the event loop for over two minutes.
test('padded sequences respect maxLength while generating', function (t) {
  var str = '{' + repeat('0', 400000) + '1..100000}';
  var startTime = Date.now();
  var expanded = expand(str);
  var elapsed = Date.now() - startTime;

  var total = totalLength(expanded);
  t.ok(
    total <= 4000000,
    'Expected total length (' + total + ') to stay bounded'
  );
  t.ok(expanded.length > 0, 'still returns a (truncated) result');
  t.ok(
    elapsed < 5000,
    'Expected time (' + elapsed + 'ms) to be less than 5000ms'
  );

  // Truncating early must not change results that fit within the bound.
  t.deepEqual(
    expand('{01..10}'),
    ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10'],
    'padded sequences under the bound are unaffected'
  );

  t.end();
});

// Bounding the intermediate `values` array must not change what `max` counts:
// alternatives that expand to nothing are dropped by `combine`, so they cost a
// slot in `values` but never a result.
test('max bounds the number of kept results', function (t) {
  t.deepEqual(
    expand('{a,,b}', { max: 2 }),
    ['a', 'b'],
    'dropped empty alternatives do not count against max'
  );
  t.deepEqual(
    expand('{a,,,b,c}', { max: 3 }),
    ['a', 'b', 'c'],
    'consecutive empty alternatives do not count against max'
  );
  // Here the empties survive as `xy`, so they are results and do count.
  t.deepEqual(
    expand('x{a,,b}y', { max: 2 }),
    ['xay', 'xy'],
    'kept empty alternatives still count against max'
  );

  t.end();
});
