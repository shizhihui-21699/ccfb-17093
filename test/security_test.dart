import 'package:test/test.dart';

import 'run_checks.dart' as scenarios;

void main() {
  test('bridge origin/frame/redirect/compatibility scenarios pass', () async {
    await scenarios.main();
  });
}
