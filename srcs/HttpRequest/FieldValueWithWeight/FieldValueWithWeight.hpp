#pragma once

# include <map>
# include <set>
# include <string>
# include "FieldValueBase.hpp"
# include "MapFieldValues.hpp"
# include "MediaType.hpp"
# include "SingleFieldValue.hpp"

class FieldValueWithWeight : public FieldValueBase {
 public:
	FieldValueWithWeight();
	FieldValueWithWeight(FieldValueBase *field_value, double weight);
	FieldValueWithWeight(const FieldValueWithWeight &other);
	virtual ~FieldValueWithWeight();

	FieldValueWithWeight &operator=(const FieldValueWithWeight &rhs);
	bool operator<(const FieldValueWithWeight &rhs) const;

	FieldValueBase *get_field_value() const;
	double get_weight() const;

	static Result<double, int> parse_valid_weight(const std::string &field_value,
												  std::size_t start_pos,
												  std::size_t *end_pos);

 private:
	FieldValueBase *field_value_;  // MediaType, SingleFieldValue, MapSetFieldValues
	double weight_;
};

class FieldValueWithWeightSet : public FieldValueBase {
 public:
	explicit FieldValueWithWeightSet(const std::set<FieldValueWithWeight> &field_values);
	FieldValueWithWeightSet(const FieldValueWithWeightSet &other);
	virtual ~FieldValueWithWeightSet();

	FieldValueWithWeightSet &operator=(const FieldValueWithWeightSet &rhs);

	std::set<FieldValueWithWeight> get_field_values() const;

 private:
	std::set<FieldValueWithWeight> field_values_;
};
