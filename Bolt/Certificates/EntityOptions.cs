namespace Bolt
{

    public sealed class EntityOptions
    {

        #region " Properties "

        public string EntityName
        {
            get { return _entityName; }
            set { _entityName = value; }
        }

        public string EmailAddress
        {
            get { return _emailAddress; }
            set { _emailAddress = value; }
        }

        public string CountryOrRegionCode
        {
            get { return _countryOrRegionCode; }
            set { _countryOrRegionCode = value; }
        }

        public string StateOrProvinceName
        {
            get { return _stateOrProvinceName; }
            set { _stateOrProvinceName = value; }
        }

        public string CityOrLocalityName
        {
            get { return _cityOrLocalityName; }
            set { _cityOrLocalityName = value; }
        }

        public string ZipOrPostalCode
        {
            get { return _zipOrPostalCode; }
            set { _zipOrPostalCode = value; }
        }

        #endregion

        #region " Members "

        private string _entityName;
        private string _emailAddress;
        private string _countryOrRegionCode;
        private string _stateOrProvinceName;
        private string _cityOrLocalityName;
        private string _zipOrPostalCode;

        #endregion

    }

}