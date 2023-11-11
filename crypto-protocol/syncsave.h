#ifndef __FU_SYNC_SAVE_H__
#define __FU_SYNC_SAVE_H__
#include <condition_variable>
#include <initializer_list>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <unordered_map>
// #if defined(__cplusplus) || defined(c_plusplus)
// extern "C" {
// #endif
// namespace utils {

/// @brief  use map 效率低
/// @tparam K
/// @tparam V
template <typename K, typename V>
class safe_map {
 public:
  safe_map() {}
  ~safe_map() {}
  safe_map(const safe_map& rhs) { map_ = rhs.map_; }
  safe_map& operator=(const safe_map& rhs) {
    if (&rhs != this) {
      map_ = rhs.map_;
    }
    return *this;
  }
  V& operator[](const K& key) { return map_[key]; }
  // when multithread calling size() return a tmp status, some threads may
  // insert just after size() call
  int size() {
    std::unique_lock<std::mutex> lock(mutex_);
    return map_.size();
  }
  // when multithread calling Empty() return a tmp status, some threads may
  // insert just after Empty() call
  bool empty() {
    std::unique_lock<std::mutex> lock(mutex_);
    return map_.empty();
  }
  bool insert(const K& key, const V& value) {
    std::unique_lock<std::mutex> lock(mutex_);
    auto ret = map_.insert(std::pair<K, V>(key, value));
    return ret.second;
  }
  void ensure_insert(const K& key, const V& value) {
    std::unique_lock<std::mutex> lock(mutex_);
    auto ret = map_.insert(std::pair<K, V>(key, value));
    // find key and cannot insert
    if (!ret.second) {
      map_.erase(ret.first);
      map_.insert(std::pair<K, V>(key, value));
      return;
    }
    return;
  }
  bool find(const K& key, V& value) {
    bool ret = false;
    std::unique_lock<std::mutex> lock(mutex_);
    auto iter = map_.find(key);
    if (iter != map_.end()) {
      value = iter->second;
      ret = true;
    }
    return ret;
  }
  bool find_old_and_set_new(const K& key, V& old_value, const V& new_value) {
    bool ret = false;
    std::unique_lock<std::mutex> lock(mutex_);
    if (map_.size() > 0) {
      auto iter = map_.find(key);
      if (iter != map_.end()) {
        old_value = iter->second;
        map_.erase(iter);
        map_.insert(std::pair<K, V>(key, new_value));
        ret = true;
      }
    }
    return ret;
  }
  void erase(const K& key) {
    std::unique_lock<std::mutex> lock(mutex_);
    map_.erase(key);
  }
  void clear() {
    std::unique_lock<std::mutex> lock(mutex_);
    map_.clear();
    return;
  }

 private:
  std::mutex mutex_;
  std::map<K, V> map_;
  // std::unordered_map<K, V> map_;
};

/// @brief use unordered_map 效率高
/// @tparam K
/// @tparam V
template <typename K, typename V>
class safe_unordered_map {
 public:
  safe_unordered_map() {}
  ~safe_unordered_map() {}
  safe_unordered_map(const safe_unordered_map& rhs) { map_ = rhs.map_; }
  safe_unordered_map& operator=(const safe_unordered_map& rhs) {
    if (&rhs != this) {
      map_ = rhs.map_;
    }
    return *this;
  }
  V& operator[](const K& key) { return map_[key]; }
  // when multithread calling size() return a tmp status, some threads may
  // insert just after size() call
  int size() {
    std::unique_lock<std::mutex> lock(mutex_);
    return map_.size();
  }
  // when multithread calling Empty() return a tmp status, some threads may
  // insert just after Empty() call
  bool empty() {
    std::unique_lock<std::mutex> lock(mutex_);
    return map_.empty();
  }
  bool insert(const K& key, const V& value) {
    std::unique_lock<std::mutex> lock(mutex_);
    auto ret = map_.insert(std::pair<K, V>(key, value));
    return ret.second;
  }
  void ensure_insert(const K& key, const V& value) {
    std::unique_lock<std::mutex> lock(mutex_);
    auto ret = map_.insert(std::pair<K, V>(key, value));
    // find key and cannot insert
    if (!ret.second) {
      map_.erase(ret.first);
      map_.insert(std::pair<K, V>(key, value));
      return;
    }
    return;
  }
  bool find(const K& key, V& value) {
    bool ret = false;
    std::unique_lock<std::mutex> lock(mutex_);
    auto iter = map_.find(key);
    if (iter != map_.end()) {
      value = iter->second;
      ret = true;
    }
    return ret;
  }
  bool find_and_erase(const K& key, V& value) {
    bool ret = false;
    std::unique_lock<std::mutex> lock(mutex_);
    auto iter = map_.find(key);
    if (iter != map_.end()) {
      value = iter->second;
      ret = true;
      map_.erase(key);
    }
    return ret;
  }
  bool find_wait(const K& key, V& value, int timeout_ms) {
    // bool ret = false;
    std::unique_lock<std::mutex> lock(mutex_);
    int step_len = 1;
    auto iter = map_.find(key);
    int all_count = timeout_ms / step_len == 0 ? 1 : timeout_ms / step_len;
    int count = 0;
    while (iter == map_.end()) {
      if (count == all_count) {
        return false;
      }
      cv_.wait_for(lock, std::chrono::milliseconds(step_len));
      count++;
      iter = map_.find(key);
    }
    value = iter->second;
    // ret = true;
    return true;
  }
  bool find_old_and_set_new(const K& key, V& old_value, const V& new_value) {
    bool ret = false;
    std::unique_lock<std::mutex> lock(mutex_);
    if (map_.size() > 0) {
      auto iter = map_.find(key);
      if (iter != map_.end()) {
        old_value = iter->second;
        map_.erase(iter);
        map_.insert(std::pair<K, V>(key, new_value));
        ret = true;
      }
    }
    return ret;
  }
  void erase(const K& key) {
    std::unique_lock<std::mutex> lock(mutex_);
    map_.erase(key);
  }
  void clear() {
    std::unique_lock<std::mutex> lock(mutex_);
    map_.clear();
    return;
  }

 private:
  std::mutex mutex_;
  //   std::map<K, V> map_;
  std::unordered_map<K, V> map_;
  std::condition_variable cv_;
};

/// @brief shared_queue, use deque,性能好
/// @tparam T
template <typename T>
class shared_queue {
 private:
  std::deque<T> queue_;
  std::mutex mutex_;
  std::condition_variable cond_;
  bool shutdown = false;
  bool not_wait = false;

 public:
  shared_queue(){};
  ~shared_queue(){};
  T& front() {
    std::unique_lock<std::mutex> mlock(mutex_);
    while (queue_.empty()) {
      cond_.wait(mlock);
    }
    return queue_.front();
  };

  bool front(T& data) {
    std::unique_lock<std::mutex> mlock(mutex_);
    while (queue_.empty()) {
      if (not_wait) {
        return false;
      }
      cond_.wait(mlock);
    }
    data = queue_.front();
    return true;
  };
  bool front_not_wait(T& data) {
    std::unique_lock<std::mutex> mlock(mutex_);
    while (queue_.empty()) {
      if (not_wait) {
        return false;
      }
      cond_.wait(mlock);
    }
    data = queue_.front();
    queue_.pop_front();
    return true;
  };
  bool front_wait(T& data, int timeout_ms) {
    std::unique_lock<std::mutex> mlock(mutex_);
    int step_len = 1000;
    int all_count = timeout_ms / step_len == 0 ? 1 : timeout_ms / step_len;
    int count = 0;
    while (queue_.empty()) {
      //   cond_.wait(mlock);
      //   std::cout << "========not_wait:" << not_wait << std::endl;
      if (not_wait || count == all_count) {
        return false;
      }
      cond_.wait_for(mlock, std::chrono::milliseconds(step_len));
      count++;
    }
    data = queue_.front();
    return true;
  };

  T pop() {
    std::unique_lock<std::mutex> mlock(mutex_);
    cond_.wait(mlock, [this]() { return !this->queue_.empty(); });
    T rc(std::move(queue_.front()));
    queue_.pop_front();
    return rc;
  };
  void pop_front() {
    std::unique_lock<std::mutex> mlock(mutex_);
    while (queue_.empty()) {
      cond_.wait(mlock);
    }
    queue_.pop_front();
  };
  void push_back(const T& item) {
    std::unique_lock<std::mutex> mlock(mutex_);
    queue_.emplace_back(item);
    mlock.unlock();      // unlock before notificiation to minimize mutex con
    cond_.notify_one();  // notify one waiting thread
  };
  void push_back(T&& item) {
    std::unique_lock<std::mutex> mlock(mutex_);
    queue_.emplace_back(std::move(item));
    mlock.unlock();      // unlock before notificiation to minimize mutex con
    cond_.notify_one();  // notify one waiting thread
  };
  void shut_down() {
    std::unique_lock<std::mutex> mlock(mutex_);
    queue_.clear();
    this->shutdown = true;
  };
  void set_not_wait() {
    std::unique_lock<std::mutex> mlock(mutex_);
    this->not_wait = true;
    cond_.notify_one();
  };
  int size() {
    std::unique_lock<std::mutex> mlock(mutex_);
    int size = queue_.size();
    mlock.unlock();
    return size;
  };
  bool empty() {
    std::unique_lock<std::mutex> mlock(mutex_);
    bool is_empty = queue_.empty();
    mlock.unlock();
    return is_empty;
  };
  bool is_shutdown() { return this->shutdown; };

 public:
  T operator[](int k) { return queue_[k]; }
};

/// @brief 线程安全队列
/// @tparam T
template <typename T>
class threadsafe_queue {
 private:
  // data_queue访问信号量
  mutable std::mutex mut;
  mutable std::condition_variable data_cond;
  using queue_type = std::queue<T>;
  queue_type data_queue;

 public:
  using value_type = typename queue_type::value_type;
  using container_type = typename queue_type::container_type;
  threadsafe_queue() = default;
  threadsafe_queue(const threadsafe_queue&) = delete;
  threadsafe_queue& operator=(const threadsafe_queue&) = delete;
  /*
   * 使用迭代器为参数的构造函数,适用所有容器对象
   * */
  template <typename _InputIterator>
  threadsafe_queue(_InputIterator first, _InputIterator last) {
    for (auto itor = first; itor != last; ++itor) {
      data_queue.push(*itor);
    }
  }
  explicit threadsafe_queue(const container_type& c) : data_queue(c) {}
  /*
   * 使用初始化列表为参数的构造函数
   * */
  threadsafe_queue(std::initializer_list<value_type> list)
      : threadsafe_queue(list.begin(), list.end()) {}
  /*
   * 将元素加入队列
   * */
  void push(const value_type& new_value) {
    std::unique_lock<std::mutex> lk(mut);
    data_queue.push(std::move(new_value));
    data_cond.notify_one();
  }

  /*
   * 从队列中弹出一个元素,如果队列为空就阻塞
   * */
  value_type wait_and_pop() {
    std::unique_lock<std::mutex> lk(mut);
    data_cond.wait(lk, [this] { return !this->data_queue.empty(); });
    auto value = std::move(data_queue.front());
    data_queue.pop();
    return value;
  }
  /*
   * 从队列中弹出一个元素,如果队列为空返回false
   * */
  bool try_pop(value_type& value) {
    std::unique_lock<std::mutex> lk(mut);
    if (data_queue.empty()) return false;
    value = std::move(data_queue.front());
    data_queue.pop();
    return true;
  }
  /*
   * 返回队列是否为空
   * */
  auto empty() const -> decltype(data_queue.empty()) {
    std::unique_lock<std::mutex> lk(mut);
    return data_queue.empty();
  }
  /*
   * 返回队列中元素数个
   * */
  auto size() const -> decltype(data_queue.size()) {
    std::unique_lock<std::mutex> lk(mut);
    return data_queue.size();
  }
};
// }  // namespace utils
// #if defined(__cplusplus) || defined(c_plusplus)
// }
// #endif
#endif
