module Yara
  # Public: Collection of ScanResult objects from YARA scanning operations.
  #
  # ScanResults acts as an enumerable container for individual rule matches,
  # providing convenient methods for accessing and querying scan results. It
  # supports standard collection operations and offers specialized methods for
  # common YARA use cases like checking for any matches or extracting rule names.
  #
  # This class is typically returned by Scanner#scan when no block is provided,
  # containing all rules that matched during the scanning operation.
  #
  # Examples
  #
  #   results = scanner.scan(data)
  #
  #   if results.matched?
  #     puts "Found #{results.size} matches"
  #     results.each { |match| puts match.rule_name }
  #   end
  #
  #   rule_names = results.matching_rules
  #   first_match = results.first
  class ScanResults
    include Enumerable

    # Public: Initialize a new ScanResults collection.
    #
    # Creates an empty results collection that can be populated with ScanResult
    # objects. This is typically called internally by Scanner during scanning
    # operations.
    #
    # results - An optional Array of ScanResult objects (default: empty array)
    #
    # Examples
    #
    #   # Typically created internally by Scanner
    #   results = ScanResults.new
    #   results << scan_result
    def initialize(results = [])
      @results = results
    end

    # Public: Enumerate over all scan results.
    #
    # Implements the Enumerable interface, allowing standard collection methods
    # like map, select, reject, etc. to be used on the results collection.
    #
    # block - Block that receives each ScanResult object
    #
    # Examples
    #
    #   results.each { |result| puts result.rule_name }
    #   matched_names = results.map(&:rule_name)
    #   malware_results = results.select { |r| r.rule_meta[:category] == 'malware' }
    #
    # Returns an Enumerator when no block given, otherwise returns self.
    def each(&block)
      @results.each(&block)
    end

    # Public: Add a ScanResult to this collection.
    #
    # This method is used internally during scanning to accumulate matching
    # rules. It appends the result to the internal results array.
    #
    # result - A ScanResult object to add to the collection
    #
    # Examples
    #
    #   results = ScanResults.new
    #   results << ScanResult.new("MyRule", rule_ptr)
    #
    # Returns self for method chaining.
    def <<(result)
      @results << result
    end

    # Public: Get all scan results as an array.
    #
    # Returns the internal array of ScanResult objects. This method is provided
    # for compatibility and direct access to the underlying collection.
    #
    # Examples
    #
    #   all_results = results.matches
    #   puts "Found #{all_results.length} matches"
    #
    # Returns an Array of ScanResult objects.
    def matches
      @results
    end

    # Public: Extract the names of all matching rules.
    #
    # This convenience method returns just the rule names from all results,
    # which is commonly needed for logging, reporting, or further processing
    # of scan results.
    #
    # Examples
    #
    #   rule_names = results.matching_rules
    #   puts "Matched: #{rule_names.join(', ')}"
    #
    # Returns an Array of String rule names.
    def matching_rules
      @results.map(&:rule_name)
    end

    # Public: Check if any rules matched during scanning.
    #
    # This is a convenience method to test whether the scan found any matches
    # without needing to check the size or examine individual results.
    #
    # Examples
    #
    #   if results.matched?
    #     puts "Scan found matches!"
    #   else
    #     puts "No matches found"
    #   end
    #
    # Returns true if there are any results, false otherwise.
    def matched?
      !@results.empty?
    end

    # Public: Alias for matched? method.
    #
    # Provides an alternative method name that may be more natural in some
    # contexts, particularly when used in conditional expressions.
    #
    # Examples
    #
    #   puts "Clean file" unless results.match?
    #
    # Returns true if there are any results, false otherwise.
    alias_method :match?, :matched?

    # Public: Get the number of matching rules.
    #
    # Returns the count of ScanResult objects in this collection, indicating
    # how many rules matched during the scan operation.
    #
    # Examples
    #
    #   puts "#{results.size} rules matched"
    #   alert_count = results.size
    #
    # Returns an Integer count of results.
    def size
      @results.size
    end

    # Public: Aliases for size method.
    #
    # These provide alternative method names for getting the collection size,
    # maintaining compatibility with standard Ruby collection interfaces.
    alias_method :length, :size
    alias_method :count, :size

    # Public: Get the first scan result.
    #
    # Returns the first ScanResult object in the collection, or nil if the
    # collection is empty. Useful when you expect only one match or want to
    # examine the first match found.
    #
    # Examples
    #
    #   first_match = results.first
    #   puts first_match.rule_name if first_match
    #
    # Returns a ScanResult object or nil if collection is empty.
    def first
      @results.first
    end

    # Public: Get the last scan result.
    #
    # Returns the last ScanResult object in the collection, or nil if the
    # collection is empty. The order depends on the sequence in which rules
    # matched during scanning.
    #
    # Examples
    #
    #   last_match = results.last
    #   puts "Final match: #{last_match.rule_name}" if last_match
    #
    # Returns a ScanResult object or nil if collection is empty.
    def last
      @results.last
    end

    # Public: Check if the results collection is empty.
    #
    # Returns true if no rules matched during scanning, false otherwise.
    # This is the inverse of matched? and can be useful for control flow.
    #
    # Examples
    #
    #   puts "No threats detected" if results.empty?
    #   process_results unless results.empty?
    #
    # Returns true if no results exist, false otherwise.
    def empty?
      @results.empty?
    end

    # Public: Convert results to a plain array.
    #
    # Returns a duplicate of the internal results array, allowing manipulation
    # without affecting the original ScanResults object. This is useful when
    # you need to work with the results as a standard Ruby array.
    #
    # Examples
    #
    #   array_copy = results.to_a
    #   sorted_results = results.to_a.sort_by(&:rule_name)
    #
    # Returns a new Array containing all ScanResult objects.
    def to_a
      @results.dup
    end
  end
end
