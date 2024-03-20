#pragma once

#include <bits/stdc++.h>
using namespace std;
namespace fucrypto {
constexpr auto DUMMY_ELEMENT = (uint64_t)-1LL;

/// @brief
class HashingTable {
 public:
  HashingTable(double epsilon) { epsilon_ = epsilon; };
  virtual ~HashingTable() = default;
  virtual bool Insert(std::uint64_t element) = 0;
  virtual bool Insert(const std::vector<std::uint64_t>& elements) = 0;
  virtual bool Print() const = 0;
  virtual std::vector<uint64_t> ObtainEntryValues() const = 0;
  virtual std::vector<std::size_t> GetNumOfElementsInBins() const = 0;
  void SetNumOfHashFunctions(std::size_t n) { num_of_hash_functions_ = n; }
  bool MapElements() {
    AllocateTable();
    MapElementsToTable();
    mapped_ = true;
    return true;
  };
  //   static std::uint64_t ElementToHash(std::uint64_t element);
 protected:
  HashingTable() = default;
  std::vector<std::uint64_t> elements_;
  // binning
  double epsilon_ = 1.2f;
  std::size_t num_bins_ = 0;
  std::size_t elem_byte_length_ = 8;
  std::size_t num_of_hash_functions_ = 2;
  // randomness
  std::size_t seed_ = 0;
  std::mt19937_64 generator_;
  // LUTs
  std::size_t num_of_luts_ = 5;
  std::size_t num_of_tables_in_lut_ = 32;
  std::vector<std::vector<std::vector<std::uint64_t>>> luts_;
  bool mapped_ = false;
  virtual bool AllocateTable() = 0;
  virtual bool MapElementsToTable() = 0;
  bool AllocateLUTs() {
    luts_.resize(num_of_hash_functions_);
    for (auto& luts : luts_) {
      luts.resize(num_of_luts_);
      for (auto& entry : luts) {
        entry.resize(num_of_tables_in_lut_);
      }
    }
    return true;
  };
  bool GenerateLUTs() {
    for (auto i = 0ull; i < num_of_hash_functions_; ++i) {
      for (auto j = 0ull; j < num_of_luts_; ++j) {
        for (auto k = 0ull; k < num_of_tables_in_lut_; k++) {
          luts_.at(i).at(j).at(k) = generator_();
        }
      }
    }
    return true;
  };
  std::vector<std::uint64_t> HashToPosition(uint64_t element) const {
    std::vector<std::uint64_t> addresses;
    for (auto func_i = 0ull; func_i < num_of_hash_functions_; ++func_i) {
      std::uint64_t address = element;
      for (auto lut_i = 0ull; lut_i < num_of_luts_; ++lut_i) {
        std::size_t lut_id =
            ((address >> (lut_i * elem_byte_length_ / num_of_luts_)) &
             0x000000FFu);
        lut_id %= num_of_tables_in_lut_;
        address ^= luts_.at(func_i).at(lut_i).at(lut_id);
      }
      addresses.push_back(address);
    }
    return addresses;
  };
};

/// @brief
class HashTableEntry {
 public:
  HashTableEntry() {
    // global_id_ = DUMMY_ELEMENT;
    // value_ = DUMMY_ELEMENT;
  }
  HashTableEntry(std::uint64_t value, std::size_t global_id,
                 std::size_t num_of_functions, std::size_t num_of_bins) {
    value_ = value;
    global_id_ = global_id;
    num_of_hash_functions_ = num_of_functions;
    num_of_bins_ = num_of_bins;
  };
  HashTableEntry(const HashTableEntry& other) {
    num_of_hash_functions_ = other.num_of_hash_functions_;
    num_of_bins_ = other.num_of_bins_;
    global_id_ = other.global_id_;
    value_ = other.value_;
    current_function_id_ = other.current_function_id_;
    possible_addresses_ = other.possible_addresses_;
  };
  void SetCurrentAddress(std::size_t function_id) {
    current_function_id_ = function_id;
  }
  void SetPossibleAddresses(std::vector<std::size_t>&& addresses) {
    possible_addresses_ = std::move(addresses);
  }
  std::size_t GetAddressAt(std::size_t function_id) const {
    return possible_addresses_.at(function_id) % num_of_bins_;
  }
  std::size_t GetCurrentFunctinId() const { return current_function_id_; }
  std::size_t GetCurrentAddress() const {
    return possible_addresses_.at(current_function_id_) % num_of_bins_;
  }
  const std::vector<std::size_t> GetPossibleAddresses() const {
    return possible_addresses_;
  };
  bool IsEmpty() const { return value_ == DUMMY_ELEMENT; }
  std::size_t GetGlobalID() const { return global_id_; }
  std::uint64_t GetElement() const { return value_; }
  void IterateFunctionNumber() {
    current_function_id_ = (current_function_id_ + 1) % num_of_hash_functions_;
  }
  friend void swap(HashTableEntry& a, HashTableEntry& b) noexcept {
    std::swap(a.value_, b.value_);
    std::swap(a.global_id_, b.global_id_);
    std::swap(a.possible_addresses_, b.possible_addresses_);
    std::swap(a.current_function_id_, b.current_function_id_);
    std::swap(a.num_of_bins_, b.num_of_bins_);
    std::swap(a.num_of_hash_functions_, b.num_of_hash_functions_);
  };

 private:
  std::size_t num_of_hash_functions_;
  std::size_t num_of_bins_;
  std::size_t global_id_ = DUMMY_ELEMENT;
  uint64_t value_ = DUMMY_ELEMENT;
  std::size_t current_function_id_ = 0;
  std::vector<std::size_t> possible_addresses_;
};

/// @brief
class CuckooTable : public HashingTable {
 public:
  CuckooTable() = delete;
  CuckooTable(double epsilon) : CuckooTable(epsilon, 0, 0){};
  CuckooTable(double epsilon, std::size_t seed)
      : CuckooTable(epsilon, 0, seed){};
  CuckooTable(std::size_t num_of_bins) : CuckooTable(0.0f, num_of_bins, 0){};
  CuckooTable(std::size_t num_of_bins, std::size_t seed)
      : CuckooTable(0.0f, num_of_bins, seed){};
  ~CuckooTable() final{};
  bool Insert(std::uint64_t element) final {
    elements_.push_back(element);
    return true;
  };
  bool Insert(const std::vector<std::uint64_t>& elements) final {
    elements_.insert(this->elements_.end(), elements.begin(), elements.end());
    return true;
  };
  void SetRecursiveInsertionLimiter(std::size_t limiter) {
    recursion_limiter_ = limiter;
  };
  bool Print() const final {
    if (!mapped_) {
      std::cout
          << "Cuckoo hashing. The table is empty. You must map elements to the "
             "table using MapElementsToTable() before you print it.\n";
      return false;
    }
    std::cout << "Cuckoo hashing - table content (the format is \"[bin#] "
                 "initial_element# element_value (function#)\"):\n";
    for (auto i = 0ull; i < hash_table_.size(); ++i) {
      const auto& entry = hash_table_.at(i);
      std::string id =
          entry.IsEmpty() ? "" : std::to_string(entry.GetGlobalID());
      std::string value =
          entry.IsEmpty() ? "" : std::to_string(entry.GetElement());
      std::string f =
          entry.IsEmpty() ? "" : std::to_string(entry.GetCurrentFunctinId());
      f = std::string("(" + f + ")");
      // std::cout << fmt::format("[{}] {} {} {}", i, id, value, f);
      // printf("[{%d}] {%s} {} {}", i, id, value, f);
      cout << "i:" << i << ",id:" << id << ",value:" << value << ",f:" << f
           << endl;
    }
    if (stash_.size() == 0) {
      std::cout << ", no stash";
    } else {
      printf(" stash has %lu elements: ", stash_.size());
      for (auto i = 0ull; i < stash_.size(); ++i) {
        std::string delimiter = i == 0 ? "" : ", ";
        //   std::cout << fmt::format("{}{} {}", delimiter,
        //   stash_.at(i).GetGlobalID(),
        //                            stash_.at(i).GetElement());
        cout << "delimiter:" << delimiter
             << ",stash_.at(i).GetGlobalID():" << stash_.at(i).GetGlobalID()
             << stash_.at(i).GetElement() << endl;
      }
    }
    std::cout << std::endl;
    return true;
  };
  auto GetStatistics() const { return statistics_; }
  auto GetStashSize() const { return stash_.size(); }
  std::vector<uint64_t> ObtainEntryValues() const final {
    std::vector<uint64_t> raw_table;
    raw_table.reserve(num_bins_);
    for (auto i = 0ull; i < num_bins_; ++i) {
      //   cout << "### i:" << i << ",v:" << hash_table_.at(i).GetElement()
      //        << ",fid:" << hash_table_.at(i).GetCurrentFunctinId() << endl;
      raw_table.push_back(
          hash_table_.at(i).GetElement() ^
          static_cast<uint64_t>(hash_table_.at(i).GetCurrentFunctinId()));
      // raw_table.push_back(hash_table_.at(i).GetElement());
    }
    return raw_table;
  };
  std::vector<uint64_t> ObtainEntryIds() const {
    std::vector<uint64_t> id_table;
    id_table.reserve(num_bins_);
    for (auto i = 0ull; i < num_bins_; ++i) {
      id_table.push_back(hash_table_.at(i).GetGlobalID());
    }
    return id_table;
  };
  std::vector<bool> ObtainBinOccupancy() const {
    // Shows whether the entry is not empty
    std::vector<bool> occ_table;
    occ_table.reserve(num_bins_);
    for (auto i = 0ull; i < num_bins_; ++i) {
      occ_table.push_back(!hash_table_.at(i).IsEmpty());
    }
    return occ_table;
  };
  std::vector<std::size_t> GetNumOfElementsInBins() const final {
    std::vector<uint64_t> num_elements_in_bins(hash_table_.size(), 0);
    for (auto i = 0ull; i < hash_table_.size(); ++i) {
      if (!hash_table_.at(i).IsEmpty()) {
        ++num_elements_in_bins.at(i);
      }
    }
    return num_elements_in_bins;
  };
  bool IsEmpty(int bin_id) const { return hash_table_.at(bin_id).IsEmpty(); };
  std::uint64_t GetElement(int bin_id) const {
    return hash_table_.at(bin_id).GetElement();
  };
  int GetCurrentFunctinId(int bin_id) const {
    return hash_table_.at(bin_id).GetCurrentFunctinId();
  };

 private:
  std::vector<HashTableEntry> hash_table_, stash_;
  std::size_t recursion_limiter_ = 200;

  struct Statistics {
    std::size_t recursive_remappings_counter_ = 0;
  } statistics_;
  CuckooTable(double epsilon, std::size_t num_of_bins, std::size_t seed) {
    epsilon_ = epsilon;
    num_bins_ = num_of_bins;
    seed_ = seed;
    generator_.seed(seed_);
  };
  bool AllocateTable() final {
    if (num_bins_ == 0 && epsilon_ == 0.0f) {
      throw(std::runtime_error(
          "You must set to a non-zero value either the number of bins or "
          "epsilon in the cuckoo hash table"));
    } else if (epsilon_ < 0.0f) {
      throw(std::runtime_error(
          "Epsilon cannot be negative in the cuckoo hash table"));
    }
    if (epsilon_ > 0.0f) {
      num_bins_ = static_cast<uint64_t>(std::ceil(elements_.size() * epsilon_));
    }
    assert(num_bins_ > 0);
    hash_table_.resize(num_bins_);
    return true;
  };
  bool MapElementsToTable() final {
    assert(!mapped_);
    AllocateLUTs();
    GenerateLUTs();
    for (auto element_id = 0ull; element_id < elements_.size(); ++element_id) {
      HashTableEntry current_entry(elements_.at(element_id), element_id,
                                   num_of_hash_functions_, num_bins_);
      // find the new element's mappings and put them to the corresponding
      // std::vector
      auto addresses = HashToPosition(elements_.at(element_id));
      current_entry.SetPossibleAddresses(std::move(addresses));
      current_entry.SetCurrentAddress(0);
      std::swap(current_entry,
                hash_table_.at(current_entry.GetCurrentAddress()));
      //   cout << ">>> element_id:" << element_id
      //        << ",val:" << current_entry.GetElement() << endl;
      for (auto recursion_step = 0ull; !current_entry.IsEmpty();
           ++recursion_step) {
        // cout << "=== cc recursion_step:" << recursion_step
        //      << ",val:" << current_entry.GetElement() << endl;

        if (recursion_step > recursion_limiter_) {
          stash_.push_back(current_entry);
          cout << "======== cc create error ======" << endl;
          exit(0);
          break;
        } else {
          ++statistics_.recursive_remappings_counter_;
          current_entry.IterateFunctionNumber();
          //   current_entry.GetCurrentAddress();
          std::swap(current_entry,
                    hash_table_.at(current_entry.GetCurrentAddress()));
        }
      }
    }
    mapped_ = true;
    return true;
  };
};
// simple_hash

/// @brief
class SimpleTable : public HashingTable {
 public:
  SimpleTable() = delete;
  SimpleTable(double epsilon) : SimpleTable(epsilon, 0, 0){};
  SimpleTable(double epsilon, std::size_t seed)
      : SimpleTable(epsilon, 0, seed){};
  SimpleTable(std::size_t num_of_bins) : SimpleTable(0.0f, num_of_bins, 0){};
  SimpleTable(std::size_t num_of_bins, std::size_t seed)
      : SimpleTable(0.0f, num_of_bins, seed){};
  ~SimpleTable() final{};
  bool Insert(std::uint64_t element) final {
    elements_.push_back(element);
    return true;
  };
  bool Insert(const std::vector<std::uint64_t>& elements) final {
    elements_.insert(this->elements_.end(), elements.begin(), elements.end());
    return true;
  };
  bool Print() const final {
    if (!mapped_) {
      std::cout
          << "Simple hashing. The table is empty. You must map elements to the "
             "table using MapElementsToTable() before you print it.\n";
      return false;
    }
    std::cout << "Simple hashing - table content (the format is \"[bin#] "
                 "initial_element# element_value (function#)\"):\n";
    for (auto bin_i = 0ull; bin_i < hash_table_.size(); ++bin_i) {
      std::string bin_delimiter = bin_i == 0 ? "" : ", ";
      // std::cout << fmt::format("{}[{}] ", bin_delimiter, bin_i);
      cout << "bin_delimiter:" << bin_delimiter << ",bin_i:" << bin_i << endl;
      for (auto entry_i = 0ull; entry_i < hash_table_.at(bin_i).size();
           ++entry_i) {
        const auto& entry = hash_table_.at(bin_i).at(entry_i);
        std::string id =
            entry.IsEmpty() ? "" : std::to_string(entry.GetGlobalID());
        std::string value =
            entry.IsEmpty() ? "" : std::to_string(entry.GetElement());
        std::string delimiter = entry_i == 0 ? "" : ", ";
        std::string f =
            entry.IsEmpty() ? "" : std::to_string(entry.GetCurrentFunctinId());
        f = std::string("(" + f + ")");
        //   std::cout << fmt::format("{}{} {} {}", delimiter, id, value, f);
        cout << "delimiter:" << delimiter << ",id:" << id << ",value:" << value
             << ",f:" << f << endl;
      }
    }
    std::cout << std::endl;
    return true;
  };
  auto GetStatistics() const { return statistics_; }
  void SetMaximumBinSize(std::size_t size) {
    maximum_bin_size_ = size;
    pad_to_maximum_bin_size = true;
  };
  std::vector<uint64_t> ObtainEntryValues() const final {
    std::vector<uint64_t> raw_table;
    raw_table.reserve(elements_.size());
    for (auto i = 0ull; i < num_bins_; ++i) {
      for (auto j = 0ull; j < hash_table_.at(i).size(); ++j) {
        raw_table.push_back(hash_table_.at(i).at(j).GetElement() ^
                            static_cast<uint64_t>(
                                hash_table_.at(i).at(j).GetCurrentFunctinId()));
        //   raw_table.push_back(hash_table_.at(i).at(j).GetElement());
      }
    }
    return raw_table;
  };
  std::vector<uint64_t> ObtainEntryValuesPadded() const {
    std::vector<uint64_t> raw_table(maximum_bin_size_ * num_bins_,
                                    DUMMY_ELEMENT);
    for (auto i = 0ull; i < num_bins_; ++i) {
      for (auto j = 0ull; j < hash_table_.at(i).size(); ++j) {
        raw_table.at(i * maximum_bin_size_ + j) =
            hash_table_.at(i).at(j).GetElement();
      }
    }
    return raw_table;
  };
  std::vector<std::vector<uint64_t>> ObtainBinEntryValues() const {
    std::vector<std::vector<uint64_t>> raw_table(num_bins_);
    for (auto i = 0ull; i < num_bins_; ++i) {
      for (auto j = 0ull; j < hash_table_.at(i).size(); ++j) {
        raw_table.at(i).push_back(
            hash_table_.at(i).at(j).GetElement() ^
            static_cast<uint64_t>(
                hash_table_.at(i).at(j).GetCurrentFunctinId()));
        //   raw_table.at(i).push_back(hash_table_.at(i).at(j).GetElement());
      }
    }
    return raw_table;
  };
  std::vector<std::vector<uint64_t>> ObtainBinEntryIds() const {
    std::vector<std::vector<uint64_t>> id_table(num_bins_);
    for (auto i = 0ull; i < num_bins_; ++i) {
      for (auto j = 0ull; j < hash_table_.at(i).size(); ++j) {
        id_table.at(i).push_back(hash_table_.at(i).at(j).GetGlobalID());
      }
    }
    return id_table;
  };
  std::vector<std::size_t> GetNumOfElementsInBins() const final {
    std::vector<uint64_t> num_elements_in_bins(hash_table_.size(), 0);
    for (auto i = 0ull; i < hash_table_.size(); ++i) {
      num_elements_in_bins.at(i) = hash_table_.at(i).size();
    }
    return num_elements_in_bins;
  };

 private:
  std::vector<std::vector<HashTableEntry>> hash_table_;
  std::size_t maximum_bin_size_ = 20;
  bool pad_to_maximum_bin_size = false;
  struct Statistics {
    std::size_t max_observed_bin_size_ = 0;
    ///< the maximum number of elements in a single bin
  } statistics_;
  SimpleTable(double epsilon, std::size_t num_of_bins, std::size_t seed) {
    epsilon_ = epsilon;
    num_bins_ = num_of_bins;
    seed_ = seed;
    generator_.seed(seed_);
  };
  bool AllocateTable() final {
    if (num_bins_ == 0 && epsilon_ == 0.0f) {
      throw(std::runtime_error(
          "You must set to a non-zero value either the number of bins or "
          "epsilon in the cuckoo hash table"));
    } else if (epsilon_ < 0) {
      throw(std::runtime_error(
          "Epsilon cannot be negative in the cuckoo hash table"));
    }
    if (epsilon_ > 0) {
      num_bins_ = static_cast<uint64_t>(std::ceil(elements_.size() * epsilon_));
    }
    assert(num_bins_ > 0);
    hash_table_.resize(num_bins_);
    return true;
  };
  bool MapElementsToTable() final {
    assert(!mapped_);
    AllocateLUTs();
    GenerateLUTs();
    for (auto element_id = 0ull; element_id < elements_.size(); ++element_id) {
      HashTableEntry current_entry(elements_.at(element_id), element_id,
                                   num_of_hash_functions_, num_bins_);
      // find the new element's mappings and put them to the corresponding
      // std::vector
      auto addresses = HashToPosition(elements_.at(element_id));
      current_entry.SetPossibleAddresses(std::move(addresses));
      for (auto i = 0ull; i < num_of_hash_functions_; ++i) {
        HashTableEntry entry_copy(current_entry);
        entry_copy.SetCurrentAddress(i);
        hash_table_.at(entry_copy.GetAddressAt(i)).push_back(entry_copy);
        auto bin_size = hash_table_.at(entry_copy.GetAddressAt(i)).size();
        if (bin_size > statistics_.max_observed_bin_size_) {
          statistics_.max_observed_bin_size_ = bin_size;
        }
      }
    }
    mapped_ = true;
    return true;
  };
};

}  // namespace fucrypto