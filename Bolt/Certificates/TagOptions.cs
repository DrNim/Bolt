using System;

namespace Bolt
{

    public sealed class TagOptions
    {

        #region " Properties "

        /// <summary>
        /// Gets the qualifier of the tag.
        /// </summary>
        /// <value>The qualifier of the tag.</value>
        public string Qualifier
        {
            get { return _qualifier; }
            set { _qualifier = value; }
        }

        /// <summary>
        /// Gets the serial number of the tag.
        /// </summary>
        /// <value>The serial number of the tag.</value>
        public Guid SerialNumber
        {
            get { return _serialNumber; }
            set { _serialNumber = value; }
        }

        /// <summary>
        /// Gets the date in local time on which the tag becomes valid.
        /// </summary>
        /// <value>A <see cref="DateTime"/> object that represents the effective date of the tag.</value>
        public DateTime NotBefore
        {
            get { return _notBefore; }
            set { _notBefore = value; }
        }

        /// <summary>
        /// Gets the date in local time after which the tage is no longer valid.
        /// </summary>
        /// <value>A <see cref="DateTime"/> object that represents the expiration date for the tag.</value>
        public DateTime NotAfter
        {
            get { return _notAfter; }
            set { _notAfter = value; }
        }

        #endregion

        #region " Members "

        private string _qualifier;
        private Guid _serialNumber;
        private DateTime _notAfter;
        private DateTime _notBefore;

        #endregion

    }

}