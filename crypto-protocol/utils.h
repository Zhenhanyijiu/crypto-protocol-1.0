#ifndef __FU_UTILS_H__
#define __FU_UTILS_H__
#include <bits/stdc++.h>
class scope_guard {
 private:
  std::function<void()> _on_exit;
  bool _dismissed;

 public:
  explicit scope_guard(std::function<void()> on_exit)
      : _on_exit(on_exit), _dismissed(false) {}
  ~scope_guard() {
    if (!_dismissed) _on_exit();
  };
  void dismiss(bool dismissed = true) { _dismissed = dismissed; };
  scope_guard() = delete;
  scope_guard(scope_guard const&) = delete;
  scope_guard& operator=(scope_guard const&) = delete;
};

#endif