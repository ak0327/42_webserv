#pragma once

# include <map>
# include <set>
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

 private:
	FieldValueBase *_field_value;  // MediaType, SingleFieldValue, MapFieldValues
	double _weight;
};

class FieldValueWithWeightSet : public FieldValueBase {
 public:
	explicit FieldValueWithWeightSet(const std::set<FieldValueWithWeight> &field_values);
	FieldValueWithWeightSet(const FieldValueWithWeightSet &other);
	virtual ~FieldValueWithWeightSet();

	FieldValueWithWeightSet &operator=(const FieldValueWithWeightSet &rhs);

	std::set<FieldValueWithWeight> get_field_values() const;

 private:
	std::set<FieldValueWithWeight> _field_values;
};
