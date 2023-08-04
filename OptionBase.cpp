#include "curlpp/OptionBase.hpp"

curlpp::OptionBase::OptionBase(CURLoption option)
	: mOption(option)
{};

curlpp::OptionBase::~OptionBase()
{};

bool curlpp::OptionBase::operator<(const curlpp::OptionBase& rhs) const
{
	return mOption < rhs.mOption;
}

CURLoption curlpp::OptionBase::getOption() const
{
	return mOption;
}